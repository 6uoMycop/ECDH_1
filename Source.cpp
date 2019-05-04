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


#define NUM 100
#define BUFLEN 1024*3

#define VERBOSE

using namespace std;

//#ifdef VERBOSE
//mutex mut_stdout;
//#endif // VERBOSE
mutex mut_stdout;//////////////////////////

mutex mut_file;
mutex mut_adj[NUM][NUM];

HANDLE hEvents_pipes[NUM][NUM] = { NULL };
HANDLE hEvents1[NUM] = { NULL };
HANDLE hEvents2[NUM] = { NULL };

HANDLE hEvents_pipes_recieved[NUM][NUM] = { NULL };

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


BOOL sendTo(uint8_t *buffer, int iLen, int iNode0, int iNode1)
{
#ifdef VERBOSE
    //mut_stdout.lock();
    //cout << "Thread " << iNode0 << ": to   " << iNode1 << " ";
    //
    //for (int j = 0; j < iLen; j++)
    //{
    //    printf("%u", buffer[j]);
    //}
    //cout << endl;
    //mut_stdout.unlock();
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
    //mut_stdout.lock();
    //cout << "Thread " << iNode0 << ": from " << iNode1 << " ";
    //for (int j = 0; j < iLen; j++)
    //{
    //    printf("%u", buffer[j]);
    //}
    //cout << endl;
    //mut_stdout.unlock();
#endif // VERBOSE

    return ret;
}

struct stRez
{
    uint8_t uiPriv[NUM][ECC_PRV_KEY_SIZE] = { 0 };
    uint8_t uiPubl[NUM][ECC_PUB_KEY_SIZE] = { 0 };
    uint8_t uiSecr[NUM][ECC_PUB_KEY_SIZE] = { 0 };
};

int iEstablishConnectionECDH(stRez* Result, int iNode0, int iNode1, int* initialized)
{
    if (iNode0 == iNode1)
    {
        return 1;
    }

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
    WaitForSingleObject(hEvents_pipes_recieved[iNode0][iNode1], INFINITE);
    ResetEvent(hEvents_pipes_recieved[iNode0][iNode1]);


    /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
    WaitForSingleObject(hEvents_pipes[iNode1][iNode0], INFINITE);
    recvFrom(pubb, ECC_PUB_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes_recieved[iNode1][iNode0]);
    ResetEvent(hEvents_pipes[iNode1][iNode0]);


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

#ifdef VERBOSE
    mut_stdout.lock();
    cout << "Connection established: " << iNode0 << "<->" << iNode1 << endl;
    mut_stdout.unlock();
#endif // VERBOSE

    return 0;
}

int iAcceptConnectionECDH(stRez* Result, int iNode0, int iNode1, int* initialized)
{
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
    SetEvent(hEvents_pipes_recieved[iNode1][iNode0]);
    ResetEvent(hEvents_pipes[iNode1][iNode0]);


    /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
    for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
    {
        prvb[i] = prng_next();
    }
    assert(ecdh_generate_keys(pubb, prvb));


    sendTo(pubb, ECC_PUB_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes[iNode0][iNode1]);
    WaitForSingleObject(hEvents_pipes_recieved[iNode0][iNode1], INFINITE);
    ResetEvent(hEvents_pipes_recieved[iNode0][iNode1]);


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
        for (int j = 0; j < iThreadNumber; j++)
        {
            if (((iThreadNumber - j) + iNumberOfNodes) % iNumberOfNodes <= iParameter / 2)
            {
                mut_adj[iThreadNumber][j].lock();
                iAdjacencyMatrix[iThreadNumber][j] = 2;
                mut_adj[iThreadNumber][j].unlock();
                iEstablishConnectionECDH(Result, iThreadNumber, j, initialized);
            }
            else
            {
                mut_adj[iThreadNumber][j].lock();
                iAdjacencyMatrix[iThreadNumber][j] = -1;
                mut_adj[iThreadNumber][j].unlock();
            }
        }
        mut_adj[iThreadNumber][((iThreadNumber + iNumberOfNodes / 2) + iNumberOfNodes) % iNumberOfNodes].lock();
        iAdjacencyMatrix[iThreadNumber][((iThreadNumber + iNumberOfNodes / 2) + iNumberOfNodes) % iNumberOfNodes] = 2;
        mut_adj[iThreadNumber][((iThreadNumber + iNumberOfNodes / 2) + iNumberOfNodes) % iNumberOfNodes].unlock();
        iEstablishConnectionECDH(Result, iThreadNumber, ((iThreadNumber + iNumberOfNodes / 2) + iNumberOfNodes) % iNumberOfNodes, initialized);
    }
    else if ((iNumberOfNodes) % 2 == 1 && (iParameter + 1) % 2 == 1)
    {
        for (int j = 0; j < iThreadNumber; j++)
        {
            if (((iThreadNumber - j) + iNumberOfNodes) % iNumberOfNodes <= iParameter / 2)
            {
                mut_adj[iThreadNumber][j].lock();
                iAdjacencyMatrix[iThreadNumber][j] = 2;
                mut_adj[iThreadNumber][j].unlock();
                iEstablishConnectionECDH(Result, iThreadNumber, j, initialized);
            }
            else
            {
                mut_adj[iThreadNumber][j].lock();
                iAdjacencyMatrix[iThreadNumber][j] = -1;
                mut_adj[iThreadNumber][j].unlock();
            }
        }
        if (iThreadNumber == 0)
        {
            mut_adj[iThreadNumber][(iNumberOfNodes - 1) / 2].lock();
            iAdjacencyMatrix[iThreadNumber][(iNumberOfNodes - 1) / 2] = 2;
            mut_adj[iThreadNumber][(iNumberOfNodes - 1) / 2].unlock();
            iEstablishConnectionECDH(Result, iThreadNumber, (iNumberOfNodes - 1) / 2, initialized);

            mut_adj[iThreadNumber][(iNumberOfNodes + 1) / 2].lock();
            iAdjacencyMatrix[iThreadNumber][(iNumberOfNodes + 1) / 2] = 2;
            mut_adj[iThreadNumber][(iNumberOfNodes + 1) / 2].unlock();
            iEstablishConnectionECDH(Result, iThreadNumber, (iNumberOfNodes + 1) / 2, initialized);
        }
        else
        {
            if (iThreadNumber + (iNumberOfNodes + 1) / 2 < iNumberOfNodes)
            {
                mut_adj[iThreadNumber][iThreadNumber + (iNumberOfNodes + 1) / 2].lock();
                iAdjacencyMatrix[iThreadNumber][iThreadNumber + (iNumberOfNodes + 1) / 2] = 2;
                mut_adj[iThreadNumber][iThreadNumber + (iNumberOfNodes + 1) / 2].unlock();
                iEstablishConnectionECDH(Result, iThreadNumber, iThreadNumber + (iNumberOfNodes + 1) / 2, initialized);
            }
        }
    }
    else
    {
        for (int j = 0; j < iThreadNumber; j++)
        {
            if (((iThreadNumber - j) + iNumberOfNodes) % iNumberOfNodes <= (iParameter + 1) / 2)
            {
                mut_adj[iThreadNumber][j].lock();
                iAdjacencyMatrix[iThreadNumber][j] = 2;
                mut_adj[iThreadNumber][j].unlock();
                iEstablishConnectionECDH(Result, iThreadNumber, j, initialized);
            }
            else
            {
                mut_adj[iThreadNumber][j].lock();
                iAdjacencyMatrix[iThreadNumber][j] = -1;
                mut_adj[iThreadNumber][j].unlock();
            }
        }
    }
}

void bob2(stRez* Result, int iThreadNumber, int iNumberOfNodes, int iParameter, int *initialized)
{
    int flag;
    int iLimit;
    (iNumberOfNodes <= iThreadNumber + iParameter / 2 + 1) ? (iLimit = iNumberOfNodes) : (iLimit = iThreadNumber + (iParameter + 1) / 2 + 1);

    while (1)
    {
        flag = 0;
        for (int i = iThreadNumber + 1; i < iLimit; i++)
        {
            mut_adj[i][iThreadNumber].lock();
            if (iAdjacencyMatrix[i][iThreadNumber] == 2)
            {
                iAdjacencyMatrix[i][iThreadNumber] = 1;
                mut_adj[i][iThreadNumber].unlock();
                iAcceptConnectionECDH(Result, iThreadNumber, i, initialized);
                flag++;
            }
            else if (iAdjacencyMatrix[i][iThreadNumber] == 1 || iAdjacencyMatrix[i][iThreadNumber] == -1)
            {
                mut_adj[i][iThreadNumber].unlock();
                flag++;
            }
            else
            {
                mut_adj[i][iThreadNumber].unlock();
            }
        }
        if (flag == iLimit - iThreadNumber - 1)
        {
            break;
        }
        Sleep(2);
    }
}



// vvv Part 2 vvv

int iFlagStartInitiation[NUM] = { 0 };
mutex mut_flags;

int iInitiator = -1;
mutex mut_initiator;
int iReciever = -1;
mutex mut_reciever;

HANDLE hEvent_initiatorStart;
HANDLE hEvent_recieverStart;

HANDLE hEvent_initiatorEnd;
HANDLE hEvent_recieverEnd;

HANDLE hEvents_helpers[NUM];

int iTotalConnections = 0;

//#define SHARED_KEY_SIZE 128 / 8
#define SHARED_KEY_SIZE 8 / 8

struct stSecrets
{
    uint8_t ui8Secret[NUM][SHARED_KEY_SIZE];
};

void vEstablishConnectionSharing(int iNode0, int iNode1, int iNumberOfNodes, uint8_t* secret)
{
    mut_stdout.lock();
    cout << "Node " << iNode0 << ": setting connection to " << iNode1 << endl;
    mut_stdout.unlock();

    uint8_t key[SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < SHARED_KEY_SIZE; i++)
    {
        key[i] = prng_next();
    }

    uint8_t b[NUM][SHARED_KEY_SIZE] = { 0 };
    uint8_t B[SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            b[i][j] = prng_next();
            B[j] ^= b[i][j];
        }
    }

    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iNode0)
        {
            sendTo(b[i], SHARED_KEY_SIZE, iNode0, i);
            SetEvent(hEvents_pipes[iNode0][i]);
            WaitForSingleObject(hEvents_pipes_recieved[iNode0][i], INFINITE);
            ResetEvent(hEvents_pipes_recieved[iNode0][i]);
        }
    }


    uint8_t c[SHARED_KEY_SIZE] = { 0 };

    WaitForSingleObject(hEvents_pipes[iNode1][iNode0], INFINITE);
    recvFrom(c, SHARED_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes_recieved[iNode1][iNode0]);
    ResetEvent(hEvents_pipes[iNode1][iNode0]);

    uint8_t A[2 * NUM][SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iNode0 && i != iNode1)
        {
            WaitForSingleObject(hEvents_pipes[i][iNode0], INFINITE);
            recvFrom(A[2 * i],     SHARED_KEY_SIZE, iNode0, i);
            SetEvent(hEvents_pipes_recieved[i][iNode0]);
            ResetEvent(hEvents_pipes[i][iNode0]);

            WaitForSingleObject(hEvents_pipes[i][iNode0], INFINITE);
            recvFrom(A[2 * i + 1], SHARED_KEY_SIZE, iNode0, i);
            SetEvent(hEvents_pipes_recieved[i][iNode0]);
            ResetEvent(hEvents_pipes[i][iNode0]);
        }
    }



    uint8_t toSend[SHARED_KEY_SIZE] = { 0 };
    for (int j = 0; j < SHARED_KEY_SIZE; j++)
    {
        toSend[j] = key[j] ^ b[iNode0][j] ^ c[j];
    }

    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            toSend[j] ^= A[2 * i + 1][j]; // нечет
        }
    }

    sendTo(toSend, SHARED_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes[iNode0][iNode1]);
    WaitForSingleObject(hEvents_pipes_recieved[iNode0][iNode1], INFINITE);
    ResetEvent(hEvents_pipes_recieved[iNode0][iNode1]);


    WaitForSingleObject(hEvents_pipes[iNode1][iNode0], INFINITE);
    recvFrom(secret, SHARED_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes_recieved[iNode1][iNode0]);
    ResetEvent(hEvents_pipes[iNode1][iNode0]);



    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iNode0 && i != iNode1)
        {
            uint8_t sec[SHARED_KEY_SIZE] = { 0 };

            WaitForSingleObject(hEvents_pipes[i][iNode0], INFINITE);
            recvFrom(sec, SHARED_KEY_SIZE, iNode0, i);
            SetEvent(hEvents_pipes_recieved[i][iNode0]);
            ResetEvent(hEvents_pipes[i][iNode0]);

            for (int j = 0; j < SHARED_KEY_SIZE; j++)
            {
                secret[j] ^= sec[j];
            }
        }
    }

    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            secret[j] ^= key[j] ^ b[iNode0][j] ^ c[j] ^ A[2 * i][j]; // чет
        }
    }

    mut_stdout.lock();
    cout << "Node " << iNode0 << ": FINISH ";
    printBits(SHARED_KEY_SIZE, secret);
    cout << endl;
    mut_stdout.unlock();
}

void vAcceptConnectionSharing(int iNode0, int iNode1, int iNumberOfNodes, uint8_t* secret)
{
    mut_stdout.lock();
    cout << "Node " << iNode0 << ": accepting connection from " << iNode1 << endl;
    mut_stdout.unlock();

    uint8_t key[SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < SHARED_KEY_SIZE; i++)
    {
        key[i] = prng_next();
    }

    uint8_t b[NUM][SHARED_KEY_SIZE] = { 0 };
    uint8_t B[SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            b[i][j] = prng_next();
            B[j] ^= b[i][j];
        }
    }



    uint8_t c[SHARED_KEY_SIZE] = { 0 };
    WaitForSingleObject(hEvents_pipes[iNode1][iNode0], INFINITE);
    recvFrom(c, SHARED_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes_recieved[iNode1][iNode0]);
    ResetEvent(hEvents_pipes[iNode1][iNode0]);




    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iNode0)
        {
            sendTo(b[i], SHARED_KEY_SIZE, iNode0, i);
            SetEvent(hEvents_pipes[iNode0][i]);
            WaitForSingleObject(hEvents_pipes_recieved[iNode0][i], INFINITE);
            ResetEvent(hEvents_pipes_recieved[iNode0][i]);
        }
    }


    uint8_t A[2 * NUM][SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iNode0 && i != iNode1)
        {
            WaitForSingleObject(hEvents_pipes[i][iNode0], INFINITE);
            recvFrom(A[2 * i], SHARED_KEY_SIZE, iNode0, i);
            SetEvent(hEvents_pipes_recieved[i][iNode0]);
            ResetEvent(hEvents_pipes[i][iNode0]);

            WaitForSingleObject(hEvents_pipes[i][iNode0], INFINITE);
            recvFrom(A[2 * i + 1], SHARED_KEY_SIZE, iNode0, i);
            SetEvent(hEvents_pipes_recieved[i][iNode0]);
            ResetEvent(hEvents_pipes[i][iNode0]);
        }
    }


    WaitForSingleObject(hEvents_pipes[iNode1][iNode0], INFINITE);
    recvFrom(secret, SHARED_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes_recieved[iNode1][iNode0]);
    ResetEvent(hEvents_pipes[iNode1][iNode0]);

    uint8_t toSend[SHARED_KEY_SIZE] = { 0 };
    for (int j = 0; j < SHARED_KEY_SIZE; j++)
    {
        toSend[j] = key[j] ^ b[iNode0][j] ^ c[j];
    }

    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            toSend[j] ^= A[2 * i][j]; // чет
        }
    }

    sendTo(toSend, SHARED_KEY_SIZE, iNode0, iNode1);
    SetEvent(hEvents_pipes[iNode0][iNode1]);
    WaitForSingleObject(hEvents_pipes_recieved[iNode0][iNode1], INFINITE);
    ResetEvent(hEvents_pipes_recieved[iNode0][iNode1]);



    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iNode0 && i != iNode1)
        {
            uint8_t sec[SHARED_KEY_SIZE] = { 0 };

            WaitForSingleObject(hEvents_pipes[i][iNode0], INFINITE);
            recvFrom(sec, SHARED_KEY_SIZE, iNode0, i);
            SetEvent(hEvents_pipes_recieved[i][iNode0]);
            ResetEvent(hEvents_pipes[i][iNode0]);

            for (int j = 0; j < SHARED_KEY_SIZE; j++)
            {
                secret[j] ^= sec[j];
            }
        }
    }

    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            secret[j] ^= key[j] ^ b[iNode0][j] ^ c[j] ^ A[2 * i + 1][j]; // нечет
        }
    }


    mut_stdout.lock();
    cout << "Node " << iNode0 << ": FINISH ";
    printBits(SHARED_KEY_SIZE, secret);
    cout << endl;
    mut_stdout.unlock();
}

void vHelperSharing(int iNode0, int iNode1, int iHelperNode, int iNumberOfNodes)
{
    mut_stdout.lock();
    cout << "Node " << iHelperNode << ": helping connect " << iNode0 << " to " << iNode1 << endl;
    mut_stdout.unlock();

    uint8_t key[SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < SHARED_KEY_SIZE; i++)
    {
        key[i] = prng_next();
    }

    uint8_t d1[NUM][SHARED_KEY_SIZE] = { 0 };
    uint8_t D[SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            d1[i][j] = prng_next();
            D[j] ^= d1[i][j];
        }
    }

    uint8_t D2[SHARED_KEY_SIZE] = { 0 };
    uint8_t d2[NUM][SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < iNumberOfNodes - 1; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            d2[i][j] = prng_next();
            D2[j] ^= d2[i][j];
        }
    }
    for (int i = 0; i < SHARED_KEY_SIZE; i++)
    {
        d2[iNumberOfNodes - 1][i] = D[i] ^ D2[i];
    }

    uint8_t c[SHARED_KEY_SIZE] = { 0 };
    uint8_t b[SHARED_KEY_SIZE] = { 0 };

    WaitForSingleObject(hEvents_pipes[iNode0][iHelperNode], INFINITE);
    recvFrom(c, SHARED_KEY_SIZE, iHelperNode, iNode0);
    SetEvent(hEvents_pipes_recieved[iNode0][iHelperNode]);
    ResetEvent(hEvents_pipes[iNode0][iHelperNode]);

    WaitForSingleObject(hEvents_pipes[iNode1][iHelperNode], INFINITE);
    recvFrom(b, SHARED_KEY_SIZE, iHelperNode, iNode1);
    SetEvent(hEvents_pipes_recieved[iNode1][iHelperNode]);
    ResetEvent(hEvents_pipes[iNode1][iHelperNode]);


    uint8_t f[2 * NUM][SHARED_KEY_SIZE] = { 0 };


    for (int i = 0, iNode = iNode0; i < 2; i++)
    {
        sendTo(d1[i], SHARED_KEY_SIZE, iHelperNode, iNode);
        SetEvent(hEvents_pipes[iHelperNode][iNode]);
        WaitForSingleObject(hEvents_pipes_recieved[iHelperNode][iNode], INFINITE);
        ResetEvent(hEvents_pipes_recieved[iHelperNode][iNode]);

        sendTo(d2[i], SHARED_KEY_SIZE, iHelperNode, iNode);
        SetEvent(hEvents_pipes[iHelperNode][iNode]);
        WaitForSingleObject(hEvents_pipes_recieved[iHelperNode][iNode], INFINITE);
        ResetEvent(hEvents_pipes_recieved[iHelperNode][iNode]);

        iNode = iNode1;
    }


    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iHelperNode && i != iNode0 && i != iNode1)
        {
            if (i < iHelperNode)
            {
                sendTo(d1[i], SHARED_KEY_SIZE, iHelperNode, i);
                SetEvent(hEvents_pipes[iHelperNode][i]);
                WaitForSingleObject(hEvents_pipes_recieved[iHelperNode][i], INFINITE);
                ResetEvent(hEvents_pipes_recieved[iHelperNode][i]);

                sendTo(d2[i], SHARED_KEY_SIZE, iHelperNode, i);
                SetEvent(hEvents_pipes[iHelperNode][i]);
                WaitForSingleObject(hEvents_pipes_recieved[iHelperNode][i], INFINITE);
                ResetEvent(hEvents_pipes_recieved[iHelperNode][i]);


                WaitForSingleObject(hEvents_pipes[i][iHelperNode], INFINITE);
                recvFrom(f[2 * i], SHARED_KEY_SIZE, iHelperNode, i);
                SetEvent(hEvents_pipes_recieved[i][iHelperNode]);
                ResetEvent(hEvents_pipes[i][iHelperNode]);

                WaitForSingleObject(hEvents_pipes[i][iHelperNode], INFINITE);
                recvFrom(f[2 * i + 1], SHARED_KEY_SIZE, iHelperNode, i);
                SetEvent(hEvents_pipes_recieved[i][iHelperNode]);
                ResetEvent(hEvents_pipes[i][iHelperNode]);
            }
            else
            {
                WaitForSingleObject(hEvents_pipes[i][iHelperNode], INFINITE);
                recvFrom(f[2 * i], SHARED_KEY_SIZE, iHelperNode, i);
                SetEvent(hEvents_pipes_recieved[i][iHelperNode]);
                ResetEvent(hEvents_pipes[i][iHelperNode]);

                WaitForSingleObject(hEvents_pipes[i][iHelperNode], INFINITE);
                recvFrom(f[2 * i + 1], SHARED_KEY_SIZE, iHelperNode, i);
                SetEvent(hEvents_pipes_recieved[i][iHelperNode]);
                ResetEvent(hEvents_pipes[i][iHelperNode]);


                sendTo(d1[i], SHARED_KEY_SIZE, iHelperNode, i);
                SetEvent(hEvents_pipes[iHelperNode][i]);
                WaitForSingleObject(hEvents_pipes_recieved[iHelperNode][i], INFINITE);
                ResetEvent(hEvents_pipes_recieved[iHelperNode][i]);

                sendTo(d2[i], SHARED_KEY_SIZE, iHelperNode, i);
                SetEvent(hEvents_pipes[iHelperNode][i]);
                WaitForSingleObject(hEvents_pipes_recieved[iHelperNode][i], INFINITE);
                ResetEvent(hEvents_pipes_recieved[iHelperNode][i]);
            }
        }
    }


    uint8_t toSend[SHARED_KEY_SIZE] = { 0 };
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            toSend[j] = key[j] ^ b[j] ^ c[j] ^ d1[iHelperNode][j] ^ f[2 * i][j]; // чет
        }
    }
    sendTo(toSend, SHARED_KEY_SIZE, iHelperNode, iNode1);
    SetEvent(hEvents_pipes[iHelperNode][iNode1]);
    WaitForSingleObject(hEvents_pipes_recieved[iHelperNode][iNode1], INFINITE);
    ResetEvent(hEvents_pipes_recieved[iHelperNode][iNode1]);

    ZeroMemory(toSend, SHARED_KEY_SIZE);
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        for (int j = 0; j < SHARED_KEY_SIZE; j++)
        {
            toSend[j] = key[j] ^ b[j] ^ c[j] ^ d2[iHelperNode][j] ^ f[2 * i + 1][j]; // нечет
        }
    }
    sendTo(toSend, SHARED_KEY_SIZE, iHelperNode, iNode0);
    SetEvent(hEvents_pipes[iHelperNode][iNode0]);
    WaitForSingleObject(hEvents_pipes_recieved[iHelperNode][iNode0], INFINITE);
    ResetEvent(hEvents_pipes_recieved[iHelperNode][iNode0]);


    mut_stdout.lock();
    cout << "Node " << iHelperNode << ": FINISH" << endl;
    mut_stdout.unlock();
}


void vSetSharing(int iThreadNumber, int iNumberOfNodes, int iParameter, stSecrets *pSecrets)
{
    int nilArr[NUM] = { 0 };

    int iLimit;
    (iNumberOfNodes <= iThreadNumber + iParameter / 2 + 1) ? (iLimit = iNumberOfNodes) : (iLimit = iThreadNumber + (iParameter + 1) / 2 + 1);

    while (1)
    {
        if (iFlagStartInitiation[iThreadNumber] == 1) // initiator
        {
            mut_initiator.lock();
            iInitiator = iThreadNumber;
            mut_initiator.unlock();

            for (int i = iLimit; i < iNumberOfNodes; i++)
            {
                ResetEvent(hEvent_initiatorEnd);

                mut_adj[iThreadNumber][i].lock();
                if (iAdjacencyMatrix[iThreadNumber][i] == -1)
                {
                    iAdjacencyMatrix[iThreadNumber][i] = 3;
                }
                mut_adj[iThreadNumber][i].unlock();


                mut_flags.lock();
                iFlagStartInitiation[i] = 2;
                for (int j = 0; j < iNumberOfNodes; j++)
                {
                    if (j != iThreadNumber && j != i)
                    {
                        iFlagStartInitiation[j] = 3;
                    }
                }
                mut_flags.unlock();


                SetEvent(hEvent_initiatorEnd);
                SetEvent(hEvent_initiatorStart);
                vEstablishConnectionSharing(iThreadNumber, i, iNumberOfNodes, pSecrets->ui8Secret[i]);
                ResetEvent(hEvent_initiatorStart);



                mut_flags.lock();
                ZeroMemory(iFlagStartInitiation, iNumberOfNodes * sizeof(int));
                iFlagStartInitiation[iThreadNumber] = 1;
                mut_flags.unlock();

                if (!(i + 1 < iNumberOfNodes))
                {
                    SetEvent(hEvent_initiatorEnd);
                    WaitForMultipleObjects(iNumberOfNodes - 2, hEvents_helpers, TRUE, INFINITE);
                }
            }


            mut_flags.lock();
            ZeroMemory(iFlagStartInitiation, iNumberOfNodes * sizeof(int));
            mut_flags.unlock();

            if (iThreadNumber + 1 < iNumberOfNodes)
            {
                mut_flags.lock();
                iFlagStartInitiation[iThreadNumber + 1] = 1;
                mut_flags.unlock();

                mut_initiator.lock();
                iInitiator = iThreadNumber + 1;
                mut_initiator.unlock();

                SetEvent(hEvent_initiatorEnd);
                WaitForMultipleObjects(iNumberOfNodes - 2, hEvents_helpers, TRUE, INFINITE);
            }
            else
            {
                SetEvent(hEvent_initiatorEnd);
                WaitForMultipleObjects(iNumberOfNodes - 2, hEvents_helpers, TRUE, INFINITE);
                break;
            }
        }
        else if (iFlagStartInitiation[iThreadNumber] == 2) // reciever
        {
            WaitForSingleObject(hEvent_initiatorStart, INFINITE);

            ResetEvent(hEvent_recieverEnd);

            mut_reciever.lock();
            iReciever = iThreadNumber;
            mut_reciever.unlock();

            mut_initiator.lock();
            int iCurInitiator = iInitiator;
            mut_initiator.unlock();


            SetEvent(hEvent_recieverStart);
            vAcceptConnectionSharing(iThreadNumber, iCurInitiator, iNumberOfNodes, pSecrets->ui8Secret[iCurInitiator]);
            ResetEvent(hEvent_recieverStart);



            mut_flags.lock();
            iFlagStartInitiation[iThreadNumber] = 0;
            mut_flags.unlock();

            mut_reciever.lock();
            iReciever = -1;
            mut_reciever.unlock();

            SetEvent(hEvent_recieverEnd);

            WaitForMultipleObjects(iNumberOfNodes - 2, hEvents_helpers, TRUE, INFINITE);
        }
        else if (iFlagStartInitiation[iThreadNumber] == 3) // helper
        {
            WaitForSingleObject(hEvent_initiatorStart, INFINITE);
            WaitForSingleObject(hEvent_recieverStart, INFINITE);

            int iEventNumber = iThreadNumber;

            mut_initiator.lock();
            int iCurInitiator = iInitiator;
            if (iCurInitiator < iThreadNumber)
            {
                iEventNumber--;
            }
            mut_initiator.unlock();

            mut_reciever.lock();
            int iCurReciever = iReciever;
            if (iCurReciever < iThreadNumber)
            {
                iEventNumber--;
            }
            mut_reciever.unlock();

            vHelperSharing(iInitiator, iReciever, iThreadNumber, iNumberOfNodes);

            SetEvent(hEvents_helpers[iEventNumber]);

            WaitForSingleObject(hEvent_initiatorEnd, INFINITE);
            WaitForSingleObject(hEvent_recieverEnd, INFINITE);

            Sleep(50);
            for (int k = 0; k < iNumberOfNodes - 2; k++)
            {
                ResetEvent(hEvents_helpers[k]);
            }

        }
        

        mut_flags.lock();
        if (memcmp(iFlagStartInitiation, nilArr, iNumberOfNodes) == 0)
        {
            mut_flags.unlock();
            break;
        }
        mut_flags.unlock();
    }
}



// ^^^ Part 2 ^^^



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
    
    ResetEvent(hEvents1[iThreadNumber]);

    stRez Result;
    int initialized = 0;
     
    if (iThreadNumber % 2 == 0)
    {
        alice2(&Result, iThreadNumber, iNumberOfNodes, iParameter, &initialized);
        bob2(&Result, iThreadNumber, iNumberOfNodes, iParameter, &initialized);
    }
    else
    {
        bob2(&Result, iThreadNumber, iNumberOfNodes, iParameter, &initialized);
        alice2(&Result, iThreadNumber, iNumberOfNodes, iParameter, &initialized);
    }


#ifdef VERBOSE
    mut_stdout.lock();
    cout << endl;
    cout << "Thread " << iThreadNumber << ":" << endl;
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        if (i != iThreadNumber && (iAdjacencyMatrix[iThreadNumber][i] == 1 || iAdjacencyMatrix[i][iThreadNumber] == 1))
        {
            cout << "To " << i << endl;
            cout << "secr: ";
            printBits(16, Result.uiSecr[i]);
            cout << endl << endl;
        }
    }
    mut_stdout.unlock();
#endif // VERBOSE
    

    SetEvent(hEvents1[iThreadNumber]);
    WaitForMultipleObjects(iNumberOfNodes, hEvents1, TRUE, INFINITE);

    stSecrets secrets;
    for (int i = 0; i < iNumberOfNodes; i++)
    {
        ZeroMemory(secrets.ui8Secret[i], SHARED_KEY_SIZE);
    }

    vSetSharing(iThreadNumber, iNumberOfNodes, iParameter, &secrets);




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

        hEvents_helpers[i] = CreateEvent(NULL, TRUE, FALSE, NULL);

        for (int j = 0; j < atoi(argv[1]); j++)
        {
            hEvents_pipes[i][j] = CreateEvent(NULL, TRUE, FALSE, NULL);
            hEvents_pipes_recieved[i][j] = CreateEvent(NULL, TRUE, FALSE, NULL);
        }
    }
    hEvent_initiatorStart = CreateEvent(NULL, TRUE, FALSE, NULL);
    hEvent_recieverStart  = CreateEvent(NULL, TRUE, FALSE, NULL);

    hEvent_initiatorEnd = CreateEvent(NULL, TRUE, FALSE, NULL);
    hEvent_recieverEnd  = CreateEvent(NULL, TRUE, FALSE, NULL);



    string fname = "time_";
    fname += argv[3];
    fname += ".txt";

    iFlagStartInitiation[0] = 1;

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
            if (iAdjacencyMatrix[i][j] == -1)
            {
                cout << "o ";
            }
            else
            {
                cout << iAdjacencyMatrix[i][j] << " ";
            }
        }
        cout << endl;
    }
    getchar();
#endif // VERBOSE

    //cout << endl;
    //for (int i = 0; i < atoi(argv[1]); i++)
    //{
    //    for (int j = 0; j < atoi(argv[1]); j++)
    //    {
    //        if (iAdjacencyMatrix[i][j] == -1)
    //        {
    //            cout << "o ";
    //        }
    //        else
    //        {
    //            cout << iAdjacencyMatrix[i][j] << " ";
    //        }
    //    }
    //    cout << endl;
    //}

    return 0;
}