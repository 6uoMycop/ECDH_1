#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <time.h>
#include <thread>
#include <vector>
#include <windows.h>
#include <mutex>

#include <assert.h>
#include "ecdh.h"



#define CBC 0
#define CTR 0
#define ECB 1

#include "AES.h"


#define NUM 50
#define BUFLEN 1024*3

//#define VERBOSE

using namespace std;

//#ifdef VERBOSE
//mutex mut_stdout;
//#endif // VERBOSE
mutex mut_stdout;//////////////////////////

mutex mut_file;
mutex mut_adj;

HANDLE hEvents_pipes[NUM][NUM] = { NULL };
HANDLE hEvents1[NUM] = { NULL };
HANDLE hEvents2[NUM] = { NULL };

int iAdjacencyMatrix[NUM][NUM] = { 0 };


struct stAnonPipe
{
    HANDLE hReadPipe;
    HANDLE hWritePipe;
    int iNode0;
    int iNode1;
};

stAnonPipe vAnonPipes[NUM][NUM];

// vvv ECDH vvv

typedef struct
{
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
    return (x << k) | (x >> (32 - k));
}

static uint32_t prng_next(void)
{
    uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);
    prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
    prng_ctx.b = prng_ctx.c + prng_ctx.d;
    prng_ctx.c = prng_ctx.d + e;
    prng_ctx.d = e + prng_ctx.a;
    return prng_ctx.d;
}

static void prng_init(uint32_t seed)
{
    uint32_t i;
    prng_ctx.a = 0xf1ea5eed;
    prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

    for (i = 0; i < 31; ++i)
    {
        (void)prng_next();
    }
}

// ^^^ ECDH ^^^



BOOL sendTo(uint8_t *buffer, int iLen, int iNode0, int iNode1)
{
#ifdef VERBOSE
    mut_stdout.lock();
    cout << "Thread " << iNode0 << ": to   " << iNode1 << " ";

    for (int j = 0; j < iLen; j++)
    {
        printf("%u", buffer[j]);
    }
    cout << endl;
    mut_stdout.unlock();
#endif // VERBOSE

    BOOL ret = WriteFile(
        vAnonPipes[iNode0][iNode1].hWritePipe,
        buffer,
        iLen,
        NULL,
        NULL
    );

    return ret;
}

BOOL recvFrom(uint8_t *buffer, int iLen, int iNode0, int iNode1)
{
    BOOL ret = ReadFile(
        vAnonPipes[iNode0][iNode1].hReadPipe,
        buffer,
        iLen,
        NULL,
        NULL
    );

#ifdef VERBOSE
    mut_stdout.lock();
    cout << "Thread " << iNode0 << ": from " << iNode1 << " ";
    for (int j = 0; j < iLen; j++)
    {
        printf("%u", buffer[j]);
    }
    cout << endl;
    mut_stdout.unlock();
#endif // VERBOSE

    return ret;
}

struct stRez
{
    uint8_t uiPriv[NUM][ECC_PRV_KEY_SIZE] = { 0 };
    uint8_t uiPubl[NUM][ECC_PUB_KEY_SIZE] = { 0 };
    uint8_t uiSecr[NUM][ECC_PUB_KEY_SIZE] = { 0 };
};

void alice(stRez *Result, int iThreadNumber)
{
    int initialized = 0;
    for (int j = 0; j < iThreadNumber; j++)
    {
        uint8_t puba[ECC_PUB_KEY_SIZE];
        uint8_t prva[ECC_PRV_KEY_SIZE];
        uint8_t seca[ECC_PUB_KEY_SIZE];
        uint8_t pubb[ECC_PUB_KEY_SIZE];
        uint32_t i;
        
        /* 0. Initialize and seed random number generator */
        if (!initialized)
        {
            ///prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
            srand(time(NULL));
            prng_init(rand());
            initialized = 1;
        }

        /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
        for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
        {
            prva[i] = prng_next();
        }
        assert(ecdh_generate_keys(puba, prva));

        sendTo(puba, ECC_PUB_KEY_SIZE, iThreadNumber, j);
        SetEvent(hEvents_pipes[iThreadNumber][j]);


        /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
        WaitForSingleObject(hEvents_pipes[j][iThreadNumber], INFINITE);
        recvFrom(pubb, ECC_PUB_KEY_SIZE, iThreadNumber, j);



        /* 3. Alice calculates S = a * Q = a * (b * g). */
        assert(ecdh_shared_secret(prva, pubb, seca));


        // Public to array
        memcpy(Result->uiPubl[j], puba, ECC_PUB_KEY_SIZE);
        // Private
        memcpy(Result->uiPriv[j], prva, ECC_PRV_KEY_SIZE);
        // Secret to array
        memcpy(Result->uiSecr[j], seca, ECC_PUB_KEY_SIZE);


        /* 4. Bob calculates T = b * P = b * (a * g). */


        /// /* 5. Assert equality, i.e. check that both parties calculated the same value. */

    }
}

void bob(stRez *Result, int iThreadNumber, int iNumberOfNodes)
{
    int initialized = 0;
    for (int j = iThreadNumber + 1; j < iNumberOfNodes; j++)
    {
        uint8_t puba[ECC_PUB_KEY_SIZE];
        uint8_t pubb[ECC_PUB_KEY_SIZE];
        uint8_t prvb[ECC_PRV_KEY_SIZE];
        uint8_t secb[ECC_PUB_KEY_SIZE];
        uint32_t i;

        /* 0. Initialize and seed random number generator */
        if (!initialized)
        {
            ///prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
            srand(time(NULL));
            prng_init(rand());
            initialized = 1;
        }

        /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
        WaitForSingleObject(hEvents_pipes[j][iThreadNumber], INFINITE);
        recvFrom(puba, ECC_PUB_KEY_SIZE, iThreadNumber, j);


        /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
        for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
        {
            prvb[i] = prng_next();
        }
        assert(ecdh_generate_keys(pubb, prvb));


        sendTo(pubb, ECC_PUB_KEY_SIZE, iThreadNumber, j);
        SetEvent(hEvents_pipes[iThreadNumber][j]);


        /* 3. Alice calculates S = a * Q = a * (b * g). */


        /* 4. Bob calculates T = b * P = b * (a * g). */
        assert(ecdh_shared_secret(prvb, puba, secb));


        // Public to array
        memcpy(Result->uiPubl[j], pubb, ECC_PUB_KEY_SIZE);
        // Private
        memcpy(Result->uiPriv[j], prvb, ECC_PRV_KEY_SIZE);
        // Secret to array
        memcpy(Result->uiSecr[j], secb, ECC_PUB_KEY_SIZE);


        /// /* 5. Assert equality, i.e. check that both parties calculated the same value. *
    }
}


int iEstablishConnectionECDH(stRez* Result, int iNode0, int iNode1, int *initialized)
{
    if (iNode0 == iNode1)
    {
        return 1;
    }
    mut_adj.lock();
    if (iNode0 < iNode1)
    {
        if (iAdjacencyMatrix[iNode0][iNode1] == 1)
        {
            mut_adj.unlock();
            return 2;
        }
        else
        {
            iAdjacencyMatrix[iNode0][iNode1] = 1;
        }
    }
    if (iNode0 > iNode1)
    {
        if (iAdjacencyMatrix[iNode1][iNode0] == 1)
        {
            mut_adj.unlock();
            return 2;
        }
        else
        {
            iAdjacencyMatrix[iNode1][iNode0] = 1;
        }
    }
    mut_adj.unlock();

    mut_stdout.lock();
    cout << "-> " << iNode0 << " " << iNode1 << endl;
    mut_stdout.unlock();
    //return 0;

    uint8_t puba[ECC_PUB_KEY_SIZE];
    uint8_t prva[ECC_PRV_KEY_SIZE];
    uint8_t seca[ECC_PUB_KEY_SIZE];
    uint8_t pubb[ECC_PUB_KEY_SIZE];
    uint32_t i;

    /* 0. Initialize and seed random number generator */
    if (!*initialized)
    {
        ///prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
        srand(time(NULL));
        prng_init(rand());
        *initialized = 1;
    }

    /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
    for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
    {
        prva[i] = prng_next();
    }
    assert(ecdh_generate_keys(puba, prva));

    sendTo(puba, ECC_PUB_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes[iNode0][iNode1]);


    /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
    WaitForSingleObject(hEvents_pipes[iNode1][iNode0], INFINITE);
    recvFrom(pubb, ECC_PUB_KEY_SIZE, iNode0, iNode1);



    /* 3. Alice calculates S = a * Q = a * (b * g). */
    assert(ecdh_shared_secret(prva, pubb, seca));


    // Public to array
    memcpy(Result->uiPubl[iNode1], puba, ECC_PUB_KEY_SIZE);
    // Private
    memcpy(Result->uiPriv[iNode1], prva, ECC_PRV_KEY_SIZE);
    // Secret to array
    memcpy(Result->uiSecr[iNode1], seca, ECC_PUB_KEY_SIZE);


    /* 4. Bob calculates T = b * P = b * (a * g). */


    /// /* 5. Assert equality, i.e. check that both parties calculated the same value. */

//#ifdef VERBOSE
    mut_stdout.lock();
    cout << "Connection established: " << iNode0 << "<->" << iNode1 << endl;
    mut_stdout.unlock();
//#endif // VERBOSE

    return 0;
}

int iAcceptConnectionECDH(stRez* Result, int iNode0, int iNode1, int *initialized)
{
    if (iNode0 == iNode1)
    {
        return 1;
    }
    mut_adj.lock();
    if (iNode0 < iNode1)
    {
        if (iAdjacencyMatrix[iNode1][iNode0] == 1)
        {
            mut_adj.unlock();
            return 2;
        }
        else
        {
            iAdjacencyMatrix[iNode1][iNode0] = 1;
        }
    }
    else // if (iNode0 > iNode1)
    {
        if (iAdjacencyMatrix[iNode0][iNode1] == 1)
        {
            mut_adj.unlock();
            return 2;
        }
        else
        {
            iAdjacencyMatrix[iNode0][iNode1] = 1;
        }
    }
    mut_adj.unlock();

    mut_stdout.lock();
    cout << "<- " << iNode0 << " " << iNode1 << endl;
    mut_stdout.unlock();
    //return 0;

    uint8_t puba[ECC_PUB_KEY_SIZE];
    uint8_t pubb[ECC_PUB_KEY_SIZE];
    uint8_t prvb[ECC_PRV_KEY_SIZE];
    uint8_t secb[ECC_PUB_KEY_SIZE];
    uint32_t i;

    /* 0. Initialize and seed random number generator */
    if (!*initialized)
    {
        ///prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
        srand(time(NULL));
        prng_init(rand());
        *initialized = 1;
    }

    /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
    WaitForSingleObject(hEvents_pipes[iNode1][iNode0], INFINITE);
    recvFrom(puba, ECC_PUB_KEY_SIZE, iNode0, iNode1);


    /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
    for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
    {
        prvb[i] = prng_next();
    }
    assert(ecdh_generate_keys(pubb, prvb));


    sendTo(pubb, ECC_PUB_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes[iNode0][iNode1]);


    /* 3. Alice calculates S = a * Q = a * (b * g). */


    /* 4. Bob calculates T = b * P = b * (a * g). */
    assert(ecdh_shared_secret(prvb, puba, secb));


    // Public to array
    memcpy(Result->uiPubl[iNode1], pubb, ECC_PUB_KEY_SIZE);
    // Private
    memcpy(Result->uiPriv[iNode1], prvb, ECC_PRV_KEY_SIZE);
    // Secret to array
    memcpy(Result->uiSecr[iNode1], secb, ECC_PUB_KEY_SIZE);


    /// /* 5. Assert equality, i.e. check that both parties calculated the same value. *

    return 0;
}

void alice2(stRez* Result, int iThreadNumber, int iNumberOfNodes, int iParameter, int *initialized)
{
    if ((iNumberOfNodes) % 2 == 0 && (iParameter + 1) % 2 == 1)
    {
        for (int j = 0; j < iNumberOfNodes; j++)
        {
            if (((iThreadNumber - j) + iNumberOfNodes) % iNumberOfNodes <= iParameter / 2)
            {
                iEstablishConnectionECDH(Result, iThreadNumber, j, initialized);
            }
        }
        iEstablishConnectionECDH(Result, iThreadNumber, ((iThreadNumber + iNumberOfNodes / 2) + iNumberOfNodes) % iNumberOfNodes, initialized);
    }
    else if ((iNumberOfNodes) % 2 == 1 && (iParameter + 1) % 2 == 1)
    {
        for (int j = 0; j < iNumberOfNodes; j++)
        {
            if (((iThreadNumber - j) + iNumberOfNodes) % iNumberOfNodes <= iParameter / 2)
            {
                iEstablishConnectionECDH(Result, iThreadNumber, j, initialized);
            }
        }
        if (iThreadNumber == 0)
        {
            iEstablishConnectionECDH(Result, iThreadNumber, (iNumberOfNodes - 1) / 2, initialized);
            iEstablishConnectionECDH(Result, iThreadNumber, (iNumberOfNodes + 1) / 2, initialized);
        }
        else
        {
            iEstablishConnectionECDH(Result, iThreadNumber, iThreadNumber + (iNumberOfNodes + 1) / 2, initialized);
        }
    }
    else
    {
        for (int j = 0; j < iNumberOfNodes; j++)
        {
            if (((iThreadNumber - j) + iNumberOfNodes) % iNumberOfNodes <= (iParameter + 1) / 2)
            {
                iEstablishConnectionECDH(Result, iThreadNumber, j, initialized);
            }
        }
    }
}

void bob2(stRez* Result, int iThreadNumber, int iNumberOfNodes, int iParameter, int *initialized)
{
    if ((iNumberOfNodes) % 2 == 0 && (iParameter + 1) % 2 == 1)
    {
        for (int j = 0; j < iNumberOfNodes; j++)
        //for (int j = iNumberOfNodes / 2; j < iNumberOfNodes; j++)
        {
            if (((j - iThreadNumber) + iNumberOfNodes) % iNumberOfNodes <= iParameter / 2)
            {
                iAcceptConnectionECDH(Result, iThreadNumber, j, initialized);
            }
            else if (iThreadNumber == ((j + iNumberOfNodes / 2) + iNumberOfNodes) % iNumberOfNodes)
            {
                iAcceptConnectionECDH(Result, iThreadNumber, ((j + iNumberOfNodes / 2) + iNumberOfNodes) % iNumberOfNodes, initialized);
            }
        }
    }
    else if ((iNumberOfNodes) % 2 == 1 && (iParameter + 1) % 2 == 1)
    {
        if (iThreadNumber == (iNumberOfNodes - 1) / 2)
        {
            iAcceptConnectionECDH(Result, iThreadNumber, 0, initialized);
        }
        else if (iThreadNumber == (iNumberOfNodes - 1) / 2)
        {
            iAcceptConnectionECDH(Result, iThreadNumber, 0, initialized);
        }

        for (int j = 0; j < iNumberOfNodes; j++)
        //for (int j = iNumberOfNodes / 2; j < iNumberOfNodes; j++)
        {
            if ((((j - iThreadNumber) + iNumberOfNodes) % iNumberOfNodes <= iParameter / 2) || (j + (iNumberOfNodes + 1) / 2))
            {
                iAcceptConnectionECDH(Result, iThreadNumber, j, initialized);
            }
        }
    }
    else
    {
        for (int j = 0; j < iNumberOfNodes; j++)
        //for (int j = iNumberOfNodes / 2; j < iNumberOfNodes; j++)
        {
            if (((j - iThreadNumber) + iNumberOfNodes) % iNumberOfNodes <= (iParameter + 1) / 2)
            {
                iAcceptConnectionECDH(Result, iThreadNumber, j, initialized);
            }
        }
    }
}



//assumes little endian
void printBits(size_t const size, void const* const ptr)
{
    unsigned char* b = (unsigned char*)ptr;
    unsigned char byte;
    int i, j;

    for (i = size - 1; i >= 0; i--)
    {
        for (j = 7; j >= 0; j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}

int worker2(int iThreadNumber, int iNumberOfNodes, int iParameter)
{
    SetEvent(hEvents1[iThreadNumber]);
    WaitForMultipleObjects(iNumberOfNodes, hEvents1, TRUE, INFINITE);

    // create pipes
    for (int i = 0; i < iThreadNumber; i++)
    {
        stAnonPipe tmp;
        if (!CreatePipe(
            &tmp.hReadPipe,
            &tmp.hWritePipe,
            NULL,
            BUFLEN
        ))
        {

#ifdef VERBOSE
            mut_stdout.lock();
            cout << "Thread " << iThreadNumber << ": error 1 in creating pipes" << endl;
            mut_stdout.unlock();
#endif // VERBOSE

            return -1;
        }
        tmp.iNode0 = iThreadNumber;
        tmp.iNode1 = i;

        vAnonPipes[iThreadNumber][i] = tmp;
        vAnonPipes[i][iThreadNumber] = tmp;
    }

#ifdef VERBOSE
    mut_stdout.lock();
    cout << "Thread " << iThreadNumber << ": created pipes" << endl;
    mut_stdout.unlock();
#endif // VERBOSE

    SetEvent(hEvents2[iThreadNumber]);
    WaitForMultipleObjects(iNumberOfNodes, hEvents2, TRUE, INFINITE);

    stRez Result;
    int initialized = 0;
     
    if (iThreadNumber % 2 == 0)
    //if (iThreadNumber < iNumberOfNodes / 2)
    {
        alice2(&Result, iThreadNumber, iNumberOfNodes, iParameter, &initialized);
        bob2(&Result, iThreadNumber, iNumberOfNodes, iParameter, &initialized);
    }
    else
    {
        bob2(&Result, iThreadNumber, iNumberOfNodes, iParameter, &initialized);
        alice2(&Result, iThreadNumber, iNumberOfNodes, iParameter, &initialized);
    }


    //alice(&Result, iThreadNumber);
    //bob(&Result, iThreadNumber, iNumberOfNodes);




#ifdef VERBOSE
    mut_stdout.lock();
    cout << endl;
    cout << "Thread " << iThreadNumber << ":" << endl;
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iThreadNumber && iAdjacencyMatrix[iThreadNumber][i] == 1)
        {
            cout << "To " << i << endl;
            cout << "secr: ";
            printBits(16, Result.uiSecr[i]);
            cout << endl << endl;
        }
    }
    mut_stdout.unlock();
#endif // VERBOSE
    

    return 0;
}

// argv[1] - total number of nodes
// argv[2] - parameter "t"
// argv[3] - experiment ID
int main(int argc, char* argv[])
{
    thread **threads = NULL;

    for (int i = 0; i < atoi(argv[1]); i++)
    {
        hEvents1[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        hEvents2[i] = CreateEvent(NULL, TRUE, FALSE, NULL);

        for (int j = 0; j < atoi(argv[1]); j++)
        {
            hEvents_pipes[i][j] = CreateEvent(NULL, TRUE, FALSE, NULL);
        }
    }


    string fname = "time_";
    fname += argv[3];
    fname += ".txt";

    threads = new thread *[atoi(argv[1])];

    clock_t uiTimeStart = clock();
    for (int i = 0; i < atoi(argv[1]); i++)
    {
        //thread tmp(worker, i, atoi(argv[1]));
        //tmp.detach();
        threads[i] = new thread(worker2, i, atoi(argv[1]), atoi(argv[2]));
    }
    for (int i = 0; i < atoi(argv[1]); i++)
    {
        threads[i]->join();
    }
    clock_t uiTimeEnd = clock();
    FILE* F = fopen(fname.c_str(), "a+");
    fprintf(F, "%d\n", uiTimeEnd - uiTimeStart);
    fclose(F);

    cout << uiTimeEnd - uiTimeStart << endl;

    delete[] threads;

#ifdef VERBOSE
    cout << endl;
    for (int i = 0; i < atoi(argv[1]); i++)
    {
        for (int j = 0; j < atoi(argv[1]); j++)
        {
            cout << iAdjacencyMatrix[i][j] << " ";
        }
        cout << endl;
    }
    getchar();
#endif // VERBOSE


    return 0;
}