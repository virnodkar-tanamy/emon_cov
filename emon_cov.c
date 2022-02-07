#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sv/svlogapi.h>
#include <sv/svlib.h>
#include <sv/intrapi.h>
#include <sv/rocket/rktloop.h> 
#include <sv/rocket/rkterr.h>

#define LOOP_COND(firstcondition)  \
        ((firstcondition) && (retStat == 0) && (mySigIntCount == 0) && (mySigAlrmCount == 0) && \
                (rc == RKT_SUCCESS) && !rctFishForError(ipcKey) && !rctEndTesting(ipcKey) && !sigFlag)

pmIPC_ID* ipcKey;
svlogHandle logHandle;
char* rkt_begin, * rkt_end, * rkt_repeat, * rkt_range;  
int rkt_begin_value;
unsigned int rkt_end_value, rkt_repeat_value, rkt_range_value;
int rkt_verify_bool, rkt_cont_bool;
char* rkt_verify, * rkt_cont, * rkt_pm;

//extern volatile int mySigIntCount, mySigAlrmCount;
volatile int mySigIntCount, mySigAlrmCount;
//extern volatile sig_atomic_t sigFlag;
volatile sig_atomic_t sigFlag;
int retStat, rc;
int first_loop;

struct sigaction mySigAction;
sigset_t sigBlockSet;
char* command;
int internal_loop_count;


void closeLog() {
    svCloseLogFile(logHandle);
}

void openLogToStderr() {
    if (svOpenLogFile(NULL, &logHandle, 0x100000, SVLOG_TSTAMP_NONE) != 0)
        exit(1);
}

void openLogToFile() {
    char    logFileName[80];

    closeLog();
    sprintf(logFileName, "./emon_cov_rand%d.log", getpid());
    if (svOpenLogFile(logFileName, &logHandle, 0x100000, SVLOG_TSTAMP_NONE) != 0)
        exit(1);
    setLogLevelCategoryHandle(logHandle);
}

int setup_pm(pmIPC_ID** ipcKey)
{
    *ipcKey = setup_pm_IPC(logHandle);

    if (*ipcKey == NULL) {
        SVLOG_ERROR(logHandle, 1, " Setup PM failed: IPC channels not acquired.\n");
        return RCTLIB_ERR_PM_IPC;
    }

    if (app2pm_Register(*ipcKey, PM_NORMAL_REG, command, getpid(), 4,
        RCG_SETUP_PHASE,
        RCG_TEST_PHASE,
        RCG_VERIFY_PHASE,
        ALL_CLEAR_PHASE) == -1) {
        SVLOG_ERROR(logHandle, 1, " Setup PM failed: Register to PM failed \n");
        return RCTLIB_ERR_PM_IPC;
    }
    return RKT_SUCCESS;
}

int call_phase_begin(pmIPC_ID* ipcKey, int phase) {
    int rc = 0;

    switch (phase) {
    case PM_REG_PHASE:                      
        rc = app2pm_TopOfLoop(1, ipcKey); //use pm,ipc key
        if (rc != RKT_SUCCESS || rctFishForError(ipcKey) || sigFlag) {
            SVLOG_ERROR(logHandle, 1, "error in top of loop registration!!\n");
        }
        break;

    case RCG_SETUP_PHASE:
        rc = iWaitForPhase(1, ipcKey, RCG_SETUP_PHASE);
        if (rc != RKT_SUCCESS || rctFishForError(ipcKey) || sigFlag) {
            SVLOG_ERROR(logHandle, 1, "error waiting for setup phase!\n");
        }
        break;

    case RCG_TEST_PHASE:
        rc = iWaitForPhase(1, ipcKey, RCG_TEST_PHASE);
        if (rc != RKT_SUCCESS || rctFishForError(ipcKey) || sigFlag) {
            SVLOG_ERROR(logHandle, 1, "error waiting for test phase!\n");
        }
        break;

    case RCG_VERIFY_PHASE:
        rc = iWaitForPhase(1, ipcKey, RCG_VERIFY_PHASE);
        // if (rc != RKT_SUCCESS || rctFishForError(ipcKey) || sigFlag) {
        if (rc != RKT_SUCCESS) {
            SVLOG_ERROR(logHandle, 1, "error waiting for verify phase!\n");
        }
        break;

    case ALL_CLEAR_PHASE:
        rc = iWaitForPhase(1, ipcKey, ALL_CLEAR_PHASE);
        // if (rc != RKT_SUCCESS || rctFishForError(ipcKey) || sigFlag) {
        if (rc != RKT_SUCCESS || rctFishForError(ipcKey)) {
            SVLOG_ERROR(logHandle, 1, "error waiting for all clear phase!\n");
        }
        break;
    }
    return rc;
}

int call_phase_end(pmIPC_ID* ipcKey, int phase) {
    int rc = 0;

    switch (phase) {
    case RCG_SETUP_PHASE:
        rc = iPhaseDone(1, ipcKey, RCG_SETUP_PHASE);
        if (rc != RKT_SUCCESS || rctFishForError(ipcKey) || sigFlag)
            SVLOG_ERROR(logHandle, 1, "error waiting for setup phase to complete!\n");
        break;

    case RCG_TEST_PHASE:
        rc = iPhaseDone(1, ipcKey, RCG_TEST_PHASE);
        if (rc != RKT_SUCCESS || rctFishForError(ipcKey) || sigFlag)
            SVLOG_ERROR(logHandle, 1, "error waiting for test phase to complete!\n");
        break;

    case RCG_VERIFY_PHASE:
        rc = iPhaseDone(1, ipcKey, RCG_VERIFY_PHASE);
        if (rc != RKT_SUCCESS)
            SVLOG_ERROR(logHandle, 1, "error waiting for verify phase to complete!\n");
        break;

    case ALL_CLEAR_PHASE:
        rc = iPhaseDone(1, ipcKey, ALL_CLEAR_PHASE);
        if (rc != RKT_SUCCESS)
            SVLOG_ERROR(logHandle, 1, "error waiting for all clear phase to complete!\n");
        break;
    }
    return rc;
}


void sigIntHandler(int signal) {
    SVLOG_INFO(logHandle, 1, "Interrupt signal handler\n");
    switch (signal) {
    case SIGALRM:
        mySigAlrmCount++;
        break;
    default:
        mySigIntCount++;
        break;
    }
    sigFlag = signal;

    if (mySigIntCount == 5)
        exit(-1);
}


int run_sync_app() {
    first_loop = 0;
    int rc = 0;
    retStat = 0;
    rkt_verify_bool = 1;
    rkt_cont_bool = 0;
    //char emon_cmd[200] = " system("emon -i icx-events.txt > coverage.dat &")"

    if (setup_pm(&ipcKey) != RKT_SUCCESS) {
        SVLOG_ERROR(logHandle, 1, "unable to talk w/ process mgr!\n");
        return(1);
    }

    // get RTM environment
    rkt_begin = getenv("RCT_BEGIN_TEST"); //begin seed number
    if (rkt_begin) {
        rkt_begin_value = atoi(rkt_begin);
        SVLOG_INFO(logHandle, 1, "begin: %d\n", rkt_begin_value);
    }
    else
        SVLOG_INFO(logHandle, 1, "begin: \"%s\"\n", rkt_begin);

    rkt_end = getenv("RCT_END_TEST"); //end seed number
    if (rkt_end) {
        rkt_end_value = atoi(rkt_end);
        SVLOG_INFO(logHandle, 1, "end: %d\n", rkt_end_value);
    }
    else
        SVLOG_INFO(logHandle, 1, "end: \"%s\"\n", rkt_end);


    rkt_repeat = getenv("RCT_RPT_TEST"); //Repeat test count
    if (rkt_repeat) {
        rkt_repeat_value = atoi(rkt_repeat);
        SVLOG_INFO(logHandle, 1, "repeat: %d\n", rkt_repeat_value);
    }
    else
        SVLOG_INFO(logHandle, 1, "repeat: \"%s\"\n", rkt_repeat);
    rkt_range = getenv("RCT_RPT_RANGE"); //repeat range count
    if (rkt_range) {
        rkt_range_value = atoi(rkt_range);
        SVLOG_INFO(logHandle, 1, "range: %d\n", rkt_range_value);
    }
    else
        SVLOG_INFO(logHandle, 1, "range: \"%s\"\n", rkt_range);
    rkt_verify = getenv("RCT_VERIFY"); //Verify turned on or off
    if (rkt_verify) {
        if (strcmp(rkt_verify, "1") == 0)
            rkt_verify_bool = 1;
        else
            rkt_verify_bool = 0;
        SVLOG_INFO(logHandle, 1, "verify: %d\n", rkt_verify_bool);
    }
    else
        SVLOG_INFO(logHandle, 1, "cont: \"%s\"\n", rkt_cont);
    rkt_cont = getenv("RCT_CONT_ON_FAIL");
    if (rkt_cont) {
        if (strcmp(rkt_cont, "1") == 0)
            rkt_cont_bool = 1;
        else
            rkt_cont_bool = 0;
        SVLOG_INFO(logHandle, 1, "cont: %d\n", rkt_cont_bool);
    }
    else
        SVLOG_INFO(logHandle, 1, "cont: \"%s\"\n", rkt_cont);


    if (call_phase_begin(ipcKey, PM_REG_PHASE) != 0)
        return 1;
    if (call_phase_begin(ipcKey, RCG_SETUP_PHASE) != 0)
        return 1;
    if (call_phase_end(ipcKey, RCG_SETUP_PHASE) != 0)
        return 1;

    SVLOG_INFO(logHandle, 1, "Starting rocket test loop\n");

    unsigned int range;
    uint64_t loopcounter = 0;
    //int flag = 0;
    // ignore -loop, -snap w/ -sync AND make work a func(verify count)
    for (range = 0; LOOP_COND(range <= rkt_range_value); range++) { //seeds 0-20 //10-20 print
        unsigned int begin;
        printf("\n 1.RANGE LOOP: %d",range);
        for (begin = 0; LOOP_COND(begin <= rkt_end_value); begin++) {
            unsigned int repeat;
            printf("\n 2.BEGIN LOOP: %d", begin);
            for (repeat = 0; LOOP_COND(repeat <= rkt_repeat_value); repeat++) { //log loop 0-20 0-20
                printf("\n 3.REPEAT LOOP: %d", repeat);
                SVLOG_INFO(logHandle, 1, "Top of loop: %ld\n", loopcounter);
                loopcounter++;

                if (first_loop++) {
                    if ((rc = call_phase_begin(ipcKey, PM_REG_PHASE)) != 0)
                        break;
                    printf("\n Reg phase");

                    if ((rc = call_phase_begin(ipcKey, RCG_SETUP_PHASE)) != 0) 
                        break;
                    printf("\n setup phase begun ");                   
                        
                    if ((rc = call_phase_end(ipcKey, RCG_SETUP_PHASE)) != 0)
                        break;
                    printf("\n  setup phase end ");

                    if(range == 0)
                       system("emon -i icx-events.txt > coverage.dat &");
                    else 
                       system("emon -resume");                        
                    }

                if ((rc = call_phase_begin(ipcKey, RCG_TEST_PHASE)) != 0) 
                    break;
                printf("\n test phase has begun");
               
                if ((rc = call_phase_end(ipcKey, RCG_TEST_PHASE)) != 0)
                        break;
                printf("\n  test phase has ended");
                //pause or stop
                if (range == rkt_range_value)
                    system("emon -stop");
                else 
                    system("emon -pause");
               
                if ((rc = call_phase_begin(ipcKey, RCG_VERIFY_PHASE)) != 0)
                    break;
                printf("\n verify phase has ended");
                if ((rc = call_phase_end(ipcKey, RCG_VERIFY_PHASE)) != 0)
                    break;
                printf("\n verify phase has ended");
                if ((rc = call_phase_begin(ipcKey, ALL_CLEAR_PHASE)) != 0)
                    break;
                printf("\n ALL_CLEAR_PHASE has begun");
                if ((rc = call_phase_end(ipcKey, ALL_CLEAR_PHASE)) != 0)
                    break;
                printf("\n ALL_CLEAR_PHASE has ended");
            }
        }
    }
    rctSmartUnregister(ipcKey, rc);
    return (0);
}

// --- main function

int main(int argc, char* argv[]) {
    
    // set up the log file
    openLogToStderr();
    openLogToFile();
    if (svSetLogLevel(logHandle, 60) != 0) {
        return 10;
    }
    SVLOG_INFO(logHandle, 1, "Log file set up complete\n");

    // set up signals
    sigFlag = 0;
    sigemptyset(&sigBlockSet);
    memset(&mySigAction, 0, sizeof(mySigAction));
    mySigAction.sa_handler = sigIntHandler;
    mySigAction.sa_mask = sigBlockSet;
    sigaction(SIGTERM, &mySigAction, NULL);
    sigaction(SIGINT, &mySigAction, NULL);
    sigaction(SIGALRM, &mySigAction, NULL);
    signal(SIGINT, sigIntHandler);
    signal(SIGTERM, sigIntHandler);
    signal(SIGALRM, sigIntHandler);

    // determine if we are a sync run or not and call the apropriate run function
    int rc = 0; 
    run_sync_app();
    return rc;
}
