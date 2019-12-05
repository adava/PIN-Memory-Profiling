/*
 * adopted from Intel fork_jit_tool.cpp file
 */
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#if defined(TARGET_MAC)
#include <sys/syscall.h>
#else
#include <syscall.h>
#endif

#include "pin.H"

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
using std::ofstream;
using std::cerr;
using std::string;
using std::endl;



namespace patch
{
    template < typename T > std::string to_string( const T& n )
    {
        std::ostringstream stm ;
        stm << n ;
        return stm.str() ;
    }
}

/* ===================================================================== */

typedef struct{
    ADDRINT start;
    ADDRINT end;
} sectionAddr;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "fork_jit_tool.out", "specify file name");

ofstream Out;
FILE * trace;
FILE * symbolsLibc;
FILE * symbolsVSFTPD;
bool read0;
bool write0;
bool firstInst;
UINT64 ipVSFTPD;
ADDRINT libcMain;
ADDRINT mainAddr;
ADDRINT spIn;
sectionAddr bssAddr = {.start=0,.end=0};
sectionAddr dataAddr;

/* ===================================================================== */


bool checkGlobals(ADDRINT ipa){
    if ((ipa>=bssAddr.start && ipa<=bssAddr.end) || (ipa>=dataAddr.start && ipa<=dataAddr.end)){
        return true;
    }
    else {
        return false;
    }
}

VOID niceMemPrint(const char *c, VOID *ip, VOID * addr)
{
    ADDRINT ipa = (ADDRINT)addr;
    string type="";
    string esps = StringFromAddrint(spIn);
    if (checkGlobals(ipa)){
        type = "global";
    }
    else {
        type = "heap";
    }
    fprintf(trace,"%s, %p, %s %p, ,%s\n", type.c_str(), ip, c, addr,esps.c_str());
}

void niceStackPrint(const char *c, const CONTEXT * ctxt, VOID * ip, VOID * addr){
    ADDRINT esp;
    ADDRINT ebp;
    ADDRINT addra = (ADDRINT)addr;
    string type="";
    string spIns = StringFromAddrint(spIn);
//    ADDRINT ipa = (ADDRINT)addr;
//    string s = StringFromAddrint(ipa);

    PIN_GetContextRegval( ctxt, REG_RSP, reinterpret_cast<UINT8*>(&esp));
    PIN_GetContextRegval( ctxt, REG_RBP, reinterpret_cast<UINT8*>(&ebp));

    string esps = StringFromAddrint(esp);
    string ebps = StringFromAddrint(ebp);

    if(addra<=spIn){
        type="local stack";
    }
    else{
        type="non-local stack";
    }

    fprintf(trace,"%s, %p, %s %p, %s, %s\n",type.c_str(), ip, c, addr,esps.c_str(),spIns.c_str());
}

// Print a memory (heap or global) read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{
    niceMemPrint("R",ip,addr);
}

// Print a memory (heap or global) write record
VOID RecordMemWrite(VOID *ip, VOID * addr)
{
    niceMemPrint("W",ip,addr);
}


// Print a stack read record
VOID RecordStackRead(const CONTEXT * ctxt, VOID * ip, VOID * addr)
{
    niceStackPrint("R",ctxt,ip,addr);
}

// Print a stack write record
VOID RecordStackWrite(const CONTEXT * ctxt, VOID * ip, VOID * addr)
{
    niceStackPrint("W",ctxt,ip,addr);
}

INT32 Usage()
{
    cerr <<
        "This pin tool tests probe replacement.\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

VOID PrintContext(const CONTEXT * ctxt, UINT64 ip, UINT64 arg)
{
    ADDRINT esp;
    ADDRINT ebp;
    //cerr << "ip inst:    " << StringFromAddrint((UINT64)ip) << endl;
    cerr << "ip:    " << StringFromAddrint(PIN_GetContextReg( ctxt, REG_INST_PTR )) << endl;
    PIN_GetContextRegval( ctxt, REG_RSP, reinterpret_cast<UINT8*>(&esp));
    cerr << "sp:    " << StringFromAddrint(esp) << endl;
    PIN_GetContextRegval( ctxt, REG_RBP, reinterpret_cast<UINT8*>(&ebp));
    cerr << "bp:    " << StringFromAddrint(ebp) << endl;
//    cerr << "gbp:   " << PIN_GetContextReg( ctxt, REG_GBP ) << endl;
//    cerr << "gs:    " << PIN_GetContextReg( ctxt, REG_SEG_GS ) << endl;
//    cerr << "gflags:" << PIN_GetContextReg( ctxt, REG_GFLAGS ) << endl;

    cerr << endl;
}



VOID getContext(const CONTEXT * ctxt, UINT64 ip, UINT64 arg)
{
    if (ip==libcMain){
        mainAddr = arg;
        //cerr << "ip inst:    " << StringFromAddrint(ip) << ", and libc main @: " << StringFromAddrint(libcMain) << ", and main @: " << StringFromAddrint(arg) << endl;
    }
    else if (mainAddr!=0 && ip==mainAddr){
        //cerr << "in main @: " << StringFromAddrint(ip) << endl;
        firstInst = false;
        PIN_GetContextRegval( ctxt, REG_RSP, reinterpret_cast<UINT8*>(&spIn));
    }
    else {
        return;
    }
    //PrintContext(ctxt,ip,arg);
}

VOID printIPSP(const CONTEXT * ctxt)
{
    ADDRINT esp;
    ADDRINT ebp;
    cerr << "ip:    " << StringFromAddrint(PIN_GetContextReg(ctxt, REG_INST_PTR )) << endl;
    PIN_GetContextRegval( ctxt, REG_RSP, reinterpret_cast<UINT8*>(&esp));
    cerr << "sp:    " << StringFromAddrint(esp) << endl;
    PIN_GetContextRegval( ctxt, REG_RBP, reinterpret_cast<UINT8*>(&ebp));
    cerr << "bp:    " << StringFromAddrint(ebp) << endl;
    cerr << endl;
}

VOID traceStack(const CONTEXT * ctxt)
{
    PIN_GetContextRegval( ctxt, REG_RSP, reinterpret_cast<UINT8*>(&spIn));
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{

//       if (INS_IsDirectControlFlow(ins))
//        if (INS_IsCall(ins))
//        {
            //ADDRINT targetAddr = INS_DirectControlFlowTargetAddress(ins);
//            if (targetAddr==libcMain){
//                cerr << "ip inst:    " << StringFromAddrint(INS_Address(ins)) << " to @: " << StringFromAddrint(targetAddr) << ", and libc main @: " << StringFromAddrint(libcMain) << endl;
//            }
//        }

    if(firstInst && libcMain!=0){
        INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)getContext,
                IARG_CONTEXT,
                IARG_INST_PTR,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_END);
        return;
    }

    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.
    if (!read0){
        return;
    }

    if(INS_IsCall(ins)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceStack,
                IARG_CONTEXT,
                IARG_END);

//        if (INS_IsValidForIpointAfter(ins)){
//            INS_InsertCall(
//                    ins, IPOINT_AFTER, /
//                    IARG_END);
//        }
    }

    if (INS_IsStackRead(ins)){
        INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordStackRead,
                IARG_CONTEXT,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, 0,
                IARG_END);
    }
    else if (INS_IsStackWrite(ins)){
        INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordStackWrite,
                IARG_CONTEXT,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, 0,
                IARG_END);
    }
    else {
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        // Iterate over each memory operand of the instruction.
        for (UINT32 memOp = 0; memOp < memOperands; memOp++)
        {
            if (INS_MemoryOperandIsRead(ins, memOp))
            {
                INS_InsertPredicatedCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                        IARG_INST_PTR,
                        IARG_MEMORYOP_EA, memOp,
                        IARG_END);
            }
            // Note that in some architectures a single memory operand can be
            // both read and written (for instance incl (%eax) on IA-32)
            // In that case we instrument it once for read and once for write.
            if (INS_MemoryOperandIsWritten(ins, memOp))
            {
                INS_InsertPredicatedCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                        IARG_INST_PTR,
                        IARG_MEMORYOP_EA, memOp,
                        IARG_END);
            }
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
    fprintf(symbolsLibc, "#eof\n");
    fprintf(symbolsVSFTPD, "#eof\n");
    fclose(symbolsVSFTPD);
    fclose(symbolsLibc);
}

void printImgType(IMG img){
    string img_type;
    const char* sectName = IMG_Name(img).c_str();
    switch (IMG_Type(img)){
        case IMG_TYPE_STATIC:
            img_type = "static";
            break;
        case IMG_TYPE_SHARED:
            img_type = "shared";
            break;
        case IMG_TYPE_SHAREDLIB:
            img_type = "shared library";
            break;
        case IMG_TYPE_RELOCATABLE:
            img_type = "relocatable";
            break;
        default:
            img_type = "unknown";
    }

    cerr << "[*] Loading image " << sectName;
    cerr << " @ " << StringFromAddrint(IMG_StartAddress(img));
    cerr << " type " << img_type << endl;
}

void printSection(SEC sec, string sec_type){
    USIZE  sec_size = SEC_Size(sec);
    cerr << "\t => Loading section " << SEC_Name(sec).c_str();
    cerr << " @ " << StringFromAddrint(SEC_Address(sec));
    cerr << " + " << patch::to_string(sec_size);
    cerr << " type " << sec_type << endl;
}

UINT64 printAndgetAddrImg(IMG img, const char *name, bool printInf){
    UINT64 sec_cont = 0;
    string img_type;
    string sec_type;
    //USIZE  sec_size;

    UINT64 ipImg = 0;
    const char* sectName = IMG_Name(img).c_str();
    if(strcmp(sectName,name)!=0){
        return ipImg;
    }
    firstInst= true;

    if(printInf){
        printImgType(img);
    }

    for (SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec=SEC_Next(sec)) {
        if (strcmp(SEC_Name(sec).c_str(),"")) {

            switch (SEC_Type(sec)){
                case SEC_TYPE_REGREL:
                    sec_type = "relocations";
                    break;
                case SEC_TYPE_DYNREL:
                    sec_type = "dynamic relocations";
                    break;
                case SEC_TYPE_EXEC:
                    sec_type = "code";
                    if(strcmp(SEC_Name(sec).c_str(),".text")==0){
                        ipImg = SEC_Address(sec);
                    }
                    break;
                case SEC_TYPE_DATA:
                    sec_type = "initialized data";
                    if(strcmp(SEC_Name(sec).c_str(),".data")==0){
                        dataAddr.start = SEC_Address(sec);
                        dataAddr.end = dataAddr.start + SEC_Size(sec);
                    }
                    break;
                case SEC_TYPE_BSS:
                    sec_type = "unitialized data";
                    if(strcmp(SEC_Name(sec).c_str(),".bss")==0){
                        bssAddr.start = SEC_Address(sec);
                        bssAddr.end = bssAddr.start + SEC_Size(sec);
                    }
                    break;
                case SEC_TYPE_LOOS:
                    sec_type = "operating system specific";
                    break;
                case SEC_TYPE_USER:
                    sec_type = "user application specific";
                    break;
                default:
                    sec_type = "unknown";
            }
            if(printInf){
                printSection(sec,sec_type);
            }
            sec_cont++;
        }
    }
    if(printInf){
        cerr << "[*] Done loading " << IMG_Name(img).c_str() << ": " << sec_cont << " sections" << endl;
    }
    return ipImg;
}

UINT64 printAndgetAddrSym(IMG img,const char *ImgName, const char *symInq, FILE * symbols) {
    const char* sectName = IMG_Name(img).c_str();
    UINT64 symAddr=0;
    if(strcmp(sectName,ImgName)==0){
        for( SYM sym= IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
            //cerr << "Symbol Name: " << SYM_Name(sym) << endl;
            const char* symbName = SYM_Name(sym).c_str();
            string sAddrPrint = StringFromAddrint(SYM_Address(sym));
            fprintf(symbols,"Symbol name:%s, Symbol Address:%s\n",symbName, sAddrPrint.c_str());
            if(strcmp(symbName,symInq)==0){
                symAddr = SYM_Address(sym);
                //cerr << "Symbol Name: " << symbName << ", Symbol Address: " << StringFromAddrint(symAddr) << endl;
                return symAddr;
            }
        }
    }
    return symAddr;
}

// Prints image and section name, type and address
VOID loadImageSec(IMG img, VOID *v)
{
    libcMain = printAndgetAddrSym(img,"/home/sina/Desktop/Research/Stateful protocol fuzzer/codes/vsftpd-3.0.3/vsftpd","__libc_start_main",symbolsVSFTPD);

    libcMain = printAndgetAddrSym(img,"/lib/x86_64-linux-gnu/libc.so.6","__libc_start_main",symbolsLibc);
    ipVSFTPD = printAndgetAddrImg(img,"/home/sina/Desktop/Research/Stateful protocol fuzzer/codes/vsftpd-3.0.3/vsftpd",false);
//    cerr << "bss start: " << StringFromAddrint(bssAddr.start) << ", and bss end: " << StringFromAddrint(bssAddr.end)<< " data start: "
//    << StringFromAddrint(dataAddr.start) << ", and data end: " << StringFromAddrint(dataAddr.end) <<  endl;
}

pid_t childPid = 0;
PIN_LOCK pinLock;
ofstream childOut;

/*
 * To make sure that before-fork callback works
 */
VOID BeforeFork(THREADID threadid, const CONTEXT* ctxt, VOID * arg)
{
    PIN_GetLock(&pinLock, threadid+1);
    Out << "TOOL: Before fork." << endl;
    PIN_ReleaseLock(&pinLock);
}

/*
 * To make sure that after-fork callback works
 * and
 * the context has the correct child pid in syscall-return register.
 * The child pid value should be equal in after-fork and after-syscall
 * callbacks.
 */
VOID AfterForkInParent(THREADID threadid, const CONTEXT* ctxt, VOID * arg)
{
    pid_t parentPid = *(pid_t*)&arg;
    PIN_GetLock(&pinLock, threadid+1);
    Out << "TOOL: After fork in parent." << endl;
    PIN_ReleaseLock(&pinLock);
    if (PIN_GetPid() != parentPid)
    {
    	cerr << "PIN_GetPid() fails in parent process" << endl;
		exit(-1);
    }
    else
    {
    	Out << "PIN_GetPid() is correct in parent process" << endl;
    }

#ifdef TARGET_BSD
    SYSCALL_STANDARD syscallStd = SYSCALL_STANDARD_IA32E_BSD;
#else
#if defined (TARGET_IA32E)
    SYSCALL_STANDARD syscallStd = SYSCALL_STANDARD_IA32E_LINUX;
#else
#ifdef TARGET_MAC
    SYSCALL_STANDARD syscallStd = SYSCALL_STANDARD_IA32_MAC;
#else
    SYSCALL_STANDARD syscallStd = SYSCALL_STANDARD_IA32_LINUX;
#endif
#endif
#endif

    pid_t afterForkChildPid = (pid_t)PIN_GetSyscallReturn(ctxt, syscallStd);
    if (!childPid)
    {
        childPid = afterForkChildPid;
    }
    else if (childPid != afterForkChildPid)
    {
        cerr << "Child pid received in syscall-after callback " <<
           childPid << " and child Pid in after-fork callback " <<
           afterForkChildPid << " don't match " << endl;
        exit(-1);
    }
}

VOID OpenChildOutput()
{
    if (!childOut.is_open())
    {
        char *outFileName = new char[KnobOutputFile.Value().size()+10];
        sprintf(outFileName, "%s_%d", KnobOutputFile.Value().c_str(), PIN_GetPid());
        childOut.open(outFileName);
    }
}

VOID AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID * arg)
{

    // After the fork, there is only one thread in the child process.  It's possible
    // that a different thread in the parent held this lock when the fork() happened.
    // Since that thread does not exist in the child, it will never release the lock.
    // Compensate by re-initializing the lock here in the child.


    PIN_GetLock(&pinLock, threadid+1);
    PIN_ReleaseLock(&pinLock);

    pid_t parentPid = *(pid_t*)&arg;

    OpenChildOutput();

    childOut << "TOOL: After fork in child." << endl;

    pid_t currentPid = PIN_GetPid();

    if ((currentPid == parentPid) || (getppid() != parentPid))
    {
		cerr << "PIN_GetPid() fails in child process" << endl;
		exit(-1);
    }
    else
    {
    	childOut << "PIN_GetPid() is correct in child process" << endl;
    }
    childOut << "Child pid " << currentPid << endl;

}

UINT32 lastSyscall = (UINT32)(-1);

VOID SyscallBefore(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD scStd,
                  VOID *arg)
{
    lastSyscall = (UINT32)PIN_GetSyscallNumber(ctxt, scStd);
    if (lastSyscall == __NR_sendto) {
        //cerr << "systemcall sendto: " << lastSyscall << endl;
    }
    else if (lastSyscall == __NR_recvfrom) {
        //cerr << "systemcall recvfrom: " << lastSyscall << endl;
    }
    else if (lastSyscall == __NR_write){
        ADDRINT fild = PIN_GetSyscallArgument(ctxt, scStd, 0);
        int fildVal = (int)fild;
        if(fildVal>=0 && fildVal<=2){
           //cerr << "write system call, file desc:"<< fildVal << endl;
        }
        if(fildVal==0){
            if(read0){
                fprintf(trace, "---Done---\n");
            }
            read0= false;
        }
    }
    else if (lastSyscall == __NR_read) {
        ADDRINT fild = PIN_GetSyscallArgument(ctxt, scStd, 0);
        int fildVal = (int)fild;
        if(fildVal>=0 && fildVal<=2){
            //cerr << "read system call, file desc:"<< fildVal << endl;
        }
        if(fildVal==0){
            read0= true;
        }
    }
}

VOID SyscallAfter(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD scStd,
                  VOID *arg)
{
    pid_t parentPid = *(pid_t*)&arg;
    pid_t currentPid = PIN_GetPid();
    if ((
#if defined (TARGET_MAC) || defined (TARGET_BSD)
         (lastSyscall == SYS_fork)
#else
         (lastSyscall == SYS_fork) || (lastSyscall == SYS_clone)
#endif
        )
        && (parentPid == currentPid))
    {
        //We are looking at ater-fork in parent
        pid_t res = PIN_GetSyscallReturn(ctxt, scStd);
        if (childPid)
        {
            if (res != childPid)
            {
                cerr << "Child pid received in after fork callback " <<
                childPid << " and child Pid in syscall-after callback " <<
                res << " don't match " << endl;
               exit(-1);
            }
        }
    }
}


int main(INT32 argc, CHAR **argv)
{
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    PIN_InitLock(&pinLock);

    PIN_InitSymbols();

    Out.open(KnobOutputFile.Value().c_str());

    unsigned long parentPid = (unsigned long)PIN_GetPid();

    firstInst= true;
    read0=write0=false;
    char *traceFileName = new char[14+10];
    sprintf(traceFileName, "pinatrace_%d.out", PIN_GetPid());
    trace = fopen(traceFileName, "w");
    fprintf(trace,"type, ip, addr, esp, initial sp\n");
    symbolsLibc = fopen("libc-symbols.out", "w");
    symbolsVSFTPD = fopen("vsftpd-symbols.out", "w");
    ipVSFTPD = 0;
    libcMain = 0;
    mainAddr = 0;
    IMG_AddInstrumentFunction(loadImageSec, 0);

    PIN_AddForkFunction(FPOINT_BEFORE, BeforeFork, (VOID*)parentPid);
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, AfterForkInParent, (VOID *)parentPid);
	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, (VOID*)parentPid);
    PIN_AddSyscallEntryFunction(SyscallBefore, 0);
    PIN_AddSyscallExitFunction(SyscallAfter, (VOID*)parentPid);

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
