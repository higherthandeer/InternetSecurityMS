
#ifndef IPTEST_DATA_QUEUE_H
#define IPTEST_DATA_QUEUE_H

#include "nids.h"
#include <pthread.h>
#ifndef CLION_DATA_QUEUE_H
#define CLION_DATA_QUEUE_H
#define MaxSize 1024
typedef struct
{
    int front;
    int rear;
    struct tcp_stream * data;
}data_queue;
data_queue *dq;//声明一个数据队列
int init_queue(data_queue *dq);
int  en_queue(data_queue *dq,struct tcp_stream *data);
int  de_queue(data_queue *dq,struct tcp_stream *data);
pthread_mutex_t http_queue_mutex;
#endif //CLION_DATA_QUEUE_H

#endif //IPTEST_DATA_QUEUE_H
