#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libnet.h>
#include <zlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include "data_queue.h"
#include "http_hash.h"
#include "nids.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>

//链路层数据包格式
typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
}ETHHEADER;
//IP层数据包格式
typedef struct {
    int header_len:4;
    int version:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}IPHEADER;
//协议映射表
char *Proto[]={
        "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};


typedef struct
{
    int count;
}HashCount;
HashCount hash_count[65535];
struct hash_list http_hashList[HashMaxSize];
//struct tcp_stream http_connection;
#define OUTBUFFLEN 65535
z_stream strm;  //声明解压流
int ret;
char **pattern,**url_pattern;
TreeNode *root,*url_root;


char ascii_string[10000];/*用于存放ASCII明文邮件内容的全局变量。*/


/*
-----------------------------------------------------------------------------------------------------------------------
下面是检测扫描用的扫描信息数据结构
-----------------------------------------------------------------------------------------------------------------------
 */
struct scan
{
    u_int addr; /* 地址 */
    unsigned short port; /* 端口号 */
    u_char flags; /* 标记 */
};
/*
-----------------------------------------------------------------------------------------------------------------------
下面是检测扫描时用到的扫描主机数据结构
-----------------------------------------------------------------------------------------------------------------------
 */
struct host
{
    struct host *next; /* 下一个主机结点 */
    struct host *prev; /* 前一个主机结点 */
    u_int addr; /* 地址 */
    int modtime; /* 时间 */
    int n_packets; /* 个数 */
    struct scan *packets; /* 扫描信息 */
};
/*
-----------------------------------------------------------------------------------------------------------------------
下面是IP协议首部的数据结构
-----------------------------------------------------------------------------------------------------------------------
 */
struct ip_header
{
#if defined(WORDS_BIGENDIAN)
    unsigned int ip_v: 4, ip_hl: 4;
#else
    unsigned int ip_hl: 4, ip_v: 4;
#endif
    unsigned int ip_tos;
    unsigned char ip_len;
    unsigned char ip_id;
    unsigned char ip_off;
    unsigned int ip_ttl;
    unsigned int ip_p;
    unsigned char ip_csum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};
/*
-----------------------------------------------------------------------------------------------------------------------
下面是TCP协议首部的数据结构
-----------------------------------------------------------------------------------------------------------------------
 */
struct tcp_header0
{
    unsigned char th_sport; /* 源端口号 */
    unsigned char th_dport; /* 目的端口号 */
    unsigned short th_seq; /* 序列号 */
    unsigned short th_ack; /* 确认号 */
#ifdef WORDS_BIGENDIAN
    unsigned int th_off: 4,  /* 数据偏移 */
        th_x2: 4; /* 保留 */
#else
    unsigned int th_x2: 4,  /* 保留 */
    th_off: 4; /* 数据偏移 */
#endif
    unsigned int th_flags;
    unsigned char th_win; /* 窗口大小 */
    unsigned char th_sum; /* 校验和 */
    unsigned char th_urp; /* 紧急指针 */
};


char* getCurrentTime() {
    struct timeval tv;
    gettimeofday(&tv, NULL); // 获取1970-1-1到现在的时间结果保存到tv中
    struct tm cur_tm; // 保存转换后的时间结果
    localtime_r((const time_t*)&tv.tv_sec, &cur_tm); // 注意这里应该是tv.tv_sec，并且应该使用const time_t*

    char* cur_time = (char*)malloc(20 * sizeof(char)); // 在堆上分配内存
    if (cur_time == NULL) {
        // 处理内存分配失败的情况
        return NULL;
    }

    snprintf(cur_time, 20, "%d-%02d-%02d %02d:%02d:%02d",
             cur_tm.tm_year + 1900, cur_tm.tm_mon + 1, cur_tm.tm_mday,
             cur_tm.tm_hour, cur_tm.tm_min, cur_tm.tm_sec);

    return cur_time;
}
// 16进制转为10进制
int char2int(char s[])
{
    char str[80];
    int k=0,m=0;
    int flag=1,mark;
    int num=0;
    for(int i=0;s[i]!='\0';i++)
        if((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')||(s[i]>='A'&&s[i]<='F'))
        {  //找出第一个十六进制字符所在的位置
            mark=i;
            break;
        }
    for(int i=0;i<mark;i++)//看看第一个十六进制字符前面有没有负号
        if(s[i]=='-')
        {
            flag=0;
            break;
        }
    for(int i=0;s[i]!='\0';i++)  //提取所有十六进制字符
        if((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')||(s[i]>='A'&&s[i]<='F'))
        {
            str[m]=s[i];
            m++;
        }
    str[m]='\0';
    for(int i=0;str[i]!='\0';i++)//将十六进制字符转换成十进制数
    {
        if(str[i]>='0'&&str[i]<='9')
            num=num*16+str[i]-'0';
        else if(str[i]>='a'&&str[i]<='f')
            num=num*16+str[i]-'a'+10;
        else if(str[i]>='A'&&str[i]<='F')
            num=num*16+str[i]-'A'+10;
    }
    if(flag==0)
        num=-num;
    //printf("%d",num);

    return num;
}
// 解压数据
char *UnCompress(char *src, int len, char **unz_data, long int *unz_len, unsigned short is_compress)
{

    char *dest = NULL;
    unsigned have;
    unsigned char out[OUTBUFFLEN];  // 解压后的报文
    int totalsize = 0;
    //allocate inflate state
    strm.avail_in = len;    //待解压数据长度
    strm.next_in = (Byte*)src; //待解压数据
    //ret = inflateInit2(&strm, 47);
    //run inflate() on input until output buffer not full
    do
    {
        strm.avail_out = OUTBUFFLEN;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);  //zlib数据解压
        if(ret!=Z_OK)
        {
            printf("Z_OK ERROR\n");
        }
        if(ret!=Z_STREAM_END)
        {
            printf("Z_STREAM_END ERROR\n");
        }
        if (ret != Z_OK && ret != Z_STREAM_END)
        {
            printf("\ninflate ret = %d\n", ret);
            //return NULL;
        }
        have = OUTBUFFLEN - strm.avail_out;
        printf("解压后的数据：\n");
        for(int i=0;i<have;i++)
        {
            printf("%c",out[i]);
        }
        printf("\n");
        totalsize += have;
        dest = (char*)realloc(dest,totalsize);
        if(dest == NULL)
        {
            perror("realloc");
            return NULL;
        }
        memcpy(dest + totalsize - have,out,have);
        dest[totalsize-1]='\0';
    } while (strm.avail_out == 0);
    //(void)inflateEnd(&strm);
    *unz_data = dest;
    *unz_len = totalsize;
    return dest;
}
// 响应报文解析
void parse_client_data(struct tcp_stream *tcp_http_connection)
{
    int len1,len2;  // 记录chunksize和chunkdata的数组的长度
    char content[65535];   // 用于存储整个HTTP内容的缓冲区
    char temp[1024];  // 临时缓冲区，用于读取或处理小块数据
    int ii;//游标，用于将数组清空
    int i,j;
    int k=0;
    int m=0;
    char *aftergzip=NULL;    // 指向解压缩后数据的指针
    long int unlength=0;    // 解压缩后的数据长度
    char entity_content[1024];  // 用于存储HTTP实体内容的缓冲区
    int number;
    char address_content[65535];  // 用于存储IP地址和端口的字符串
    // 从tcp_http_connection中提取IP地址和端口信息
    struct tuple4 ip_and_port=tcp_http_connection->addr;
    // 将源IP地址转换为字符串并存储到address_content中
    strcpy(address_content,inet_ntoa(*((
            struct in_addr *) &(ip_and_port.saddr))));
    // 在address_content后追加源端口号
    sprintf(address_content+strlen(address_content),":%i",ip_and_port.source);
    // 分隔符
    strcat(address_content,"-1-----------------------1-");
    // 将目标IP地址转换为字符串并追加到address_content中
    strcat(address_content,inet_ntoa(*((
            struct in_addr *) & (ip_and_port.daddr))));
    // 在address_content后追加目标端口号
    sprintf(address_content+strlen(address_content),":%i",ip_and_port.dest);
    strcat(address_content,"\n");
    // 打印IP地址和端口信息
    printf("address_content=\n%s\n",address_content);
    // 使用IP地址和端口信息计算哈希值
    unsigned hash=hash_key(tcp_http_connection->addr);
    hash_node *p=http_hashList[hash].first;
    if(p==NULL)
    {
        printf("p为空\n");
    } else{
        while(p)
        {
            if(tuple_cmp(tcp_http_connection->addr,p->tupl4))  // 使用tuple_cmp函数比较tcp_http_connection的addr和p的tupl4字段
            {
                printf("开始解析\n");
                // 打印新的数据长度，client.count_new表示TCP连接中客户端方向新到达的数据的字节数
                printf("count_new=%d\n",tcp_http_connection->client.count_new);
                // 将tcp_http_connection的client数据复制到content中
                memcpy(content,tcp_http_connection->client.data,tcp_http_connection->client.count_new);
                // 存储数据长度到number变量
                number=tcp_http_connection->client.count_new;
                // 检查content的前四个字符是否为"HTTP"，同时检查p->is_text是否为0
                if(content[0]!='H'&&content[1]!='T'&&content[2]!='T'&&content[3]!='P'&&p->is_text!=0) {
                    if(p->is_monitor)//已经监测到关键字
                    {
                        return;
                    }
                    printf("实体内容为（1 续）:\n");
                    if(p->is_chunked)    // 如果数据是chunked传输的
                    {
                        printf("chunk(xu)\n");
                        // 循环处理number长度的数据
                        for(m=0;m<number;m++)
                        {
                            if(p->count==0)//记录长度
                            {
                                // 检查是否到达了chunked数据的结尾（由"\r\n\r\n"标识）
                                if(content[m+1]=='\r'&&content[m+2]=='\n'&&content[m+3]=='\r'&&content[m+4]=='\n')//结尾
                                {
                                    printf("最后一个包\n");
                                    break;
                                }
                                else if (content[m] != '\r' && content[m + 1] != '\n') {  // 如果不是结尾，且不是换行符，记录到p->size中
                                    p->size[p->size_q] = content[m];
                                    p->size_q++;
                                    //printf("aaa%s\n", p->size);
                                }
                                else   // 如果是换行符，增加p->count的值并跳过当前和下一个字符
                                {
                                    //printf("bbb%s\n", p->size);
                                    p->count++;
                                    m++;
                                    continue;
                                }
                            }
                            else//记录数据
                            {
                                p->length=char2int(p->size);
                                if(p->size_p<p->length)     // size_p记录size_data数组的长度
                                {
                                    p->size_data[p->size_p++]=content[m];
                                } else
                                {
                                    p->size_data[p->size_p] = '\0';
                                    m++;
                                    p->count=0;
                                    printf("size(xu)=%s\n",p->size);
                                    printf("q(xu)=%d\n",p->size_q);
                                    printf("p(xu)=%d\n", p->size_p);
                                    p->size_q=0;
                                    p->size_data[p->size_p]='\0';
                                    printf("----------1111111---------\n");
                                    UnCompress(p->size_data,p->size_p,&aftergzip,&unlength,1);
                                    p->is_monitor=Search_acTrie(root,p->state_node,aftergzip,strlen(aftergzip),pattern);
                                    len1=strlen(p->size);
                                    len2=strlen(p->size_data);
                                    // 重置
                                    for(ii=0;ii<len1;ii++)
                                    {
                                        p->size[ii]='\0';
                                    }
                                    for(ii=0;ii<len2;ii++)
                                    {
                                        p->size_data[ii]='\0';
                                    }
                                    p->size_p=0;
                                    p->length=0;
                                    if(p->is_monitor)//如果命中,写日志
                                    {
                                        printf("我命中了\n");
                                        FILE *file = fopen("/home/higherthandeer/CLionProjects/netSecurity/log/content_log.txt", "a");
                                        if(file==NULL)
                                        {
                                            printf("open error\n");
                                            break;
                                        }
                                        char ip_match[16];
                                        char keyword[256];
                                        strcpy(ip_match,inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
                                        char local_ip[16];
                                        strcpy(local_ip,inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
                                        fputs("本地ip:",file);
                                        fputs(local_ip,file);
                                        fputs("\t本地端口:",file);
                                        fprintf(file,"%d",p->tupl4.source);
                                        fputs("\t\t访问服务器ip:",file);
                                        fputs(ip_match,file);
                                        fputs("\t\t访问服务器端口:",file);
                                        fprintf(file,"%d",p->tupl4.dest);
                                        //fputc(p->tupl4.dest,file);
                                        fputs("\ttime:",file);
                                        fputs(getCurrentTime(),file);
                                        memcpy(keyword,pattern[p->is_monitor-1],strlen(pattern[p->is_monitor-1]));
                                        keyword[strlen(pattern[p->is_monitor-1])]='\0';
                                        fputs("\t监测关键字:",file);
                                        fputs(keyword,file);
                                        fputs("\n",file);
                                        fclose(file);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        printf("不是chunk2\n");
                        if(p->is_compresss)
                        {
                            printf("16进制\n");
                            char *sll=content;
                            for(int ii=0;ii<strlen(content);ii++)
                            {
                                printf("%2x",(unsigned char)*(sll+ii));
                            }
                            if(p->is_monitor)
                            {
                                return;
                            }
                            /*if(p->is_monitor)//命中
                            {
                                printf("匹配成功\n");
                                break;
                            }else{*/
                            UnCompress(content,number,&aftergzip,&unlength,p->is_compresss);
                            p->is_monitor=Search_acTrie(root,p->state_node,aftergzip,(int)strlen(aftergzip),pattern);
                            if(p->is_monitor)//如果命中,写日志
                            {
                                printf("我命中了\n");
                                FILE *file = fopen("/home/higherthandeer/CLionProjects/netSecurity/log/content_log.txt", "a");
                                if(file==NULL)
                                {
                                    printf("open error\n");
                                    break;
                                }
                                char ip_match[16];
                                char keyword[256];
                                strcpy(ip_match,inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
                                char local_ip[16];
                                strcpy(local_ip,inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
                                fputs("本地ip:",file);
                                fputs(local_ip,file);
                                fputs("\t本地端口:",file);
                                fprintf(file,"%d",p->tupl4.source);
                                fputs("\t\t访问服务器ip:",file);
                                fputs(ip_match,file);
                                fputs("\t\t访问服务器端口:",file);
                                fprintf(file,"%d",p->tupl4.dest);
                                fputs("\ttime:",file);
                                fputs(getCurrentTime(),file);
                                memcpy(keyword,pattern[p->is_monitor-1],strlen(pattern[p->is_monitor-1]));
                                keyword[strlen(pattern[p->is_monitor-1])]='\0';
                                fputs("\t监测关键字:",file);
                                fputs(keyword,file);
                                fputs("\n",file);
                                fclose(file);
                            }


                        } else
                        {
                            printf("%s\n",content);
                            printf("----------333333333---------\n");
                            Search_acTrie(root,p->state_node,content,number,pattern);
                        }
                    }
                    //UnCompress(content,number,&aftergzip,&unlength,1);

                }
                else {
                    for(int ii=0;ii<65535;ii++)//数组清空
                    {
                        p->size[ii]='\0';
                        p->size_data[ii]='\0';
                    }
                    p->size_p=0;
                    p->size_q=0;
                    p->count=0;
                    p->length=0;
                    p->is_monitor=0;
                    strm.zalloc = Z_NULL;
                    strm.zfree = Z_NULL;
                    strm.opaque = Z_NULL;
                    strm.avail_in = 0;
                    strm.next_in = Z_NULL;
                    ret = inflateInit2(&strm, 47);
                    if (ret != Z_OK) {
                        printf("初始化失败\n");
                        return;
                    }
                    for (i = 0; i < strlen(content); i++) {
                        if (content[i] != '\n') {
                            k++;
                            continue;
                        }
                        for (j = 0; j < k; j++) {
                            temp[j] = content[j + i - k];
                        }
                        temp[j] = '\0';
                        if (strstr(temp, "Date")) {
                            printf("当前的时间为(Date):%s\n", temp + strlen("Date"));
                            printf("%s\n", temp);
                        }
                        if (strstr(temp, "Server")) {
                            printf("服务器(Server)：%s\n", temp + strlen("Server"));
                            printf("%s\n", temp);
                        }
                        if (strstr(temp, "Cache-Control")) {
                            printf("缓存机制为(Cache-Control):%s\n", temp + strlen("Cache-Control:"));
                        }
                        if (strstr(temp, "Content-Length")) {
                            printf("内容长度为(Content-Length):%s\n", temp + strlen("Content-Length:"));
                        }
                        if (strstr(temp, "Content-Type")) {
                            printf("内容类型(Content-Type):%s\n", temp + strlen("Content-Type"));
                        }
                        if (strstr(temp, "Content-Encoding")) {
                            printf("内容类型(Content-Encoding):%s\n", temp + strlen("Content-Encoding"));
                        }
                        /*获取实体内容*/
                        if ((content[i] == '\n') && (content[i + 1] == '\r')) {
                            if (i + 3 == strlen(content)) {
                                printf("无实体内容\n");
                                break;
                            }
                            for (j = 0; j < number - i - 3; j++)
                                entity_content[j] = content[i + 3 + j];
                            entity_content[j]='\0';   // 存储的报文数据
                            printf("实体内容为:\n");
                            if(p->is_text)
                            {
                                if(p->is_chunked)
                                {
                                    printf("chunk\n");
                                    // chunk数据块的处理
                                    for(m=0;m<j;m++)
                                    {
                                        if(p->count==0)//记录chunksize
                                        {
                                            if (entity_content[m] != '\r' && entity_content[m + 1] != '\n') {
                                                p->size[p->size_q++] = entity_content[m];  // p-size叔祖存储chunksize
                                            }
                                            else
                                            {
                                                p->count++;
                                                m++;
                                                continue;
                                            }
                                        }
                                        else//记录数据chunkdata
                                        {
                                            p->length=char2int(p->size);
                                            if(p->size_p<p->length)
                                            {
                                                p->size_data[p->size_p++]=entity_content[m];  // p->size_data存储chunkdata
                                            }
                                            else
                                            {
                                                p->size_data[p->size_p] = '\0';
                                                m++;
                                                p->count=0;
                                                printf("size=%s\n",p->size);
                                                printf("q=%d\n",p->size_q);
                                                printf("p=%d\n", p->size_p);
                                                p->size_q=0;
                                                if(p->is_monitor)
                                                {
                                                    return;
                                                }
                                                UnCompress(p->size_data,p->size_p,&aftergzip,&unlength,1);
                                                printf("----------44444444---------\n");
                                                p->is_monitor=Search_acTrie(root,p->state_node,aftergzip,strlen(aftergzip),pattern);
                                                len1=strlen(p->size);
                                                len2=strlen(p->size_data);
                                                for(ii=0;ii<len1;ii++)
                                                {
                                                    p->size[ii]='\0';
                                                }
                                                for(ii=0;ii<len2;ii++)
                                                {
                                                    p->size_data[ii]='\0';
                                                }
                                                p->length=0;
                                                p->size_p=0;
                                                if(p->is_monitor)
                                                {
                                                    printf("我命中了\n");
                                                    FILE *file = fopen("/home/higherthandeer/CLionProjects/netSecurity/log/content_log.txt", "a");
                                                    if(file==NULL)
                                                    {
                                                        printf("open error\n");
                                                        break;
                                                    }
                                                    char ip_match[16];
                                                    char keyword[256];
                                                    strcpy(ip_match,inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
                                                    char local_ip[16];
                                                    strcpy(local_ip,inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
                                                    fputs("本地ip:",file);
                                                    fputs(local_ip,file);
                                                    fputs("\t本地端口:",file);
                                                    fprintf(file,"%d",p->tupl4.source);
                                                    fputs("\t\t访问服务器ip:",file);
                                                    fputs(ip_match,file);
                                                    fputs("\t\t访问服务器端口:",file);
                                                    fprintf(file,"%d",p->tupl4.dest);
                                                    fputs("\ttime:",file);
                                                    fputs(getCurrentTime(),file);
                                                    memcpy(keyword,pattern[p->is_monitor-1],strlen(pattern[p->is_monitor-1]));
                                                    keyword[strlen(pattern[p->is_monitor-1])]='\0';
                                                    fputs("\t监测关键字:",file);
                                                    fputs(keyword,file);
                                                    fputs("\n",file);
                                                    fclose(file);
                                                }
                                            }
                                        }
                                    }
                                } else
                                {
                                    printf("不是chunk\n");
                                    if(p->is_compresss)
                                    {
                                        if(p->is_monitor)
                                        {
                                            return;
                                        }
                                        UnCompress(entity_content,j,&aftergzip,&unlength,p->is_compresss);
                                        p->is_monitor=Search_acTrie(root,p->state_node,aftergzip,strlen(aftergzip),pattern);
                                        if(p->is_monitor)
                                        {
                                            printf("我命中了\n");
                                            FILE *file = fopen("/home/higherthandeer/CLionProjects/netSecurity/log/content_log.txt", "a");
                                            if(file==NULL)
                                            {
                                                printf("open error\n");
                                                break;
                                            }
                                            char ip_match[16];
                                            char keyword[256];
                                            strcpy(ip_match,inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
                                            char local_ip[16];
                                            strcpy(local_ip,inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
                                            fputs("本地ip:",file);
                                            fputs(local_ip,file);
                                            fputs("\t本地端口:",file);
                                            fprintf(file,"%d",p->tupl4.source);
                                            fputs("\t\t访问服务器ip:",file);
                                            fputs(ip_match,file);
                                            fputs("\t\t访问服务器端口:",file);
                                            fprintf(file,"%d",p->tupl4.dest);
                                            fputs("\ttime:",file);
                                            fputs(getCurrentTime(),file);
                                            memcpy(keyword,pattern[p->is_monitor-1],strlen(pattern[p->is_monitor-1]));
                                            keyword[strlen(pattern[p->is_monitor-1])]='\0';
                                            fputs("\t监测关键字:",file);
                                            fputs(keyword,file);
                                            fputs("\n",file);
                                            fclose(file);
                                        }

                                    } else
                                    {
                                        printf("%s\n",entity_content);
                                        printf("----------66666666---------\n");
                                    }

                                }
                            } else{
                                printf("不是html\n");
                                return;
                            }
                            break;
                        }
                        k = 0;
                    }
                }


                return;
            } else
                p=p->next;
        }
    }
}
// 请求报文解析
void parse_server_data(char content[],int number,struct tcp_stream *tcp_http_connection)
{
    TreeNode **state_node=(TreeNode **) malloc(sizeof(TreeNode)); //流式匹配状态指针
    *state_node=NULL;
    char url[2048]={'\0'};
    char temp[1024];
    char str1[512];
    char str2[512];
    char str3[512];
    int i=0,j=0,k=0;
    //char entity_content[1024];
    for(i=0;i<(int)strlen(content);i++)
    {
        if(content[i]!='\n')
        {
            k++;
            continue;
        }
        for(j=0;j<k;j++)
        {
            temp[j]=content[j+i-k];
        }
        temp[j]='\0';
        if(strstr(temp,"GET"))     // temp响应头信息
        {
            printf("请求行为：");
            printf("%s\n",temp);
            sscanf(temp,"%s %s %s",str1,str2,str3);
            printf("使用的命令为：%s\n",str1);
            printf("获得的资源为：%s\n",str2);
            printf("HTTP协议类型为：%s\n",str3);
        }
        if(strstr(temp,"Referer"))
        {
            printf("转移地址为(Referer):%s\n",temp+strlen("Referer:"));
        }
        if(strstr(temp,"Accept-Language"))
            printf("使用的语言为（Accept-language）:%s\n",temp+strlen("Accept-Language:"));
        if(strstr(temp,"Accept-Encoding"))
            printf("接收的编码为(Accept-Encoding):%s\n",temp+strlen("Accept-Encoding:"));
        if(strstr(temp,"Host"))
        {
            printf("访问的主机为（Host）:%s\n",temp+strlen("Host: "));
            int ii;
            for(ii=0;temp[ii]!='\r';ii++)
            {
                url[ii]=temp[(int)strlen("Host: ")+ii];
            }
            int len=(int)strlen(url)-1;
            for(ii=0;ii<strlen(str2);ii++)
            {
                url[len+ii]=str2[ii];
            }
            return;
        }
        k=0;
    }
}
void http_protocol_callback(struct tcp_stream* tcp_http_connection,void **param)
{
    char ip_input[16];
    unsigned int hash;
    char address_content[1024];
    char content[65535];
    struct tuple4 ip_and_port=tcp_http_connection->addr;
    strcpy(ip_input,inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
    printf("访问网页服务器ip=%s\n",ip_input); // update

    strcpy(address_content,inet_ntoa(*((
            struct in_addr *) &(ip_and_port.saddr))));
    sprintf(address_content+strlen(address_content),":%i",ip_and_port.source);
    strcat(address_content,"<---->");
    strcat(address_content,inet_ntoa(*((
            struct in_addr *) & (ip_and_port.daddr))));
    sprintf(address_content+strlen(address_content),":%i",ip_and_port.dest);
    strcat(address_content,"\n");
    if(tcp_http_connection->nids_state==NIDS_JUST_EST)
    {
        tcp_http_connection->client.collect++;//浏览器接受数据
        tcp_http_connection->server.collect++;//web服务器接收数据
        printf("\n\n===============\n\n");
        printf("%s建立连接\n",address_content);
        return;
    }
    if(tcp_http_connection->nids_state==NIDS_CLOSE)
    {

        printf("--------------\n");
        printf("%s连接正常关闭\n",address_content);
        delete_hash_node(http_hashList,tcp_http_connection->addr);
        return;
    }
    if(tcp_http_connection->nids_state==NIDS_RESET)
    {
        printf("--------------\n");
        printf("%s连接被reset关闭\n",address_content);
        return;
    }
    if(tcp_http_connection->nids_state==NIDS_DATA)
    {
        struct half_stream *hlf;
        if(tcp_http_connection->client.count_new)//浏览器接收数据 client.count_new 为真时为响应报文，否则为请求报文
        {

            printf("浏览器接收数据\n");
            en_queue(dq,tcp_http_connection);//数据进队列
            ////1-2到时候需要写到analysis线程中
            ////1
            de_queue(dq,tcp_http_connection);
            hash=hash_key(tcp_http_connection->addr);
            printf("hash1=%d\n",hash);
            hash_count[hash].count++;
            if(hash_count[hash].count==1)
            {
                insert_hash(*tcp_http_connection,http_hashList);
            }
            parse_client_data(tcp_http_connection);//分析web服务器接收的数据
        }
        else{
            hash=hash_key(tcp_http_connection->addr);
            hlf=&(tcp_http_connection->server);//hlf表示服务端的连接端
            strcpy(address_content,inet_ntoa(*((
                    struct in_addr *) &(ip_and_port.saddr))));
            sprintf(address_content+strlen(address_content),":%i",ip_and_port.source);
            strcat(address_content,"---->");
            strcat(address_content,inet_ntoa(*((
                    struct in_addr *) & (ip_and_port.daddr))));
            sprintf(address_content+strlen(address_content),":%i",ip_and_port.dest);
            strcat(address_content,"\n");
            printf("\n");
            printf("%s",address_content);
            printf("服务端接收数据...\n");
            printf("\n");
            memcpy(content,hlf->data,hlf->count_new);
            content[hlf->count_new]='\0';
            parse_server_data(content,hlf->count_new,tcp_http_connection);//分析web服务器接收的数据
        }
    }
    return;
}


//回调函数
void pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    ETHHEADER *eth_header=(ETHHEADER*)pkt_data;
    printf("---------------开始分析-----------------\n");
    printf("----------------------------------------------\n");
    printf("数据包长度: %d \n",header->len);
    //解析数据包IP头部
    if(header->len>=14){
        IPHEADER *ip_header=(IPHEADER*)(pkt_data+14);
        //解析协议类型
        char strType[100];
        if(ip_header->proto>7)
            strcpy(strType,"IP/UNKNWN");
        else
            strcpy(strType,Proto[ip_header->proto]);

        printf("源   MAC : %02X-%02X-%02X-%02X-%02X-%02X==>",eth_header->SrcMac[0],eth_header->SrcMac[1],eth_header->SrcMac[2],eth_header->SrcMac[3],eth_header->SrcMac[4],eth_header->SrcMac[5]);
        printf("目的  MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->DestMac[0],eth_header->DestMac[1],eth_header->DestMac[2],eth_header->DestMac[3],eth_header->DestMac[4],eth_header->DestMac[5]);

        printf("源   IP : %d.%d.%d.%d==>",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);
        printf("目的  IP : %d.%d.%d.%d\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);

        printf("协议 : %s\n",strType);

        //显示数据帧内容
        int i;
        for(i=0; i<(int)header->len; ++i)  {
            printf(" %02x", pkt_data[i]);
            if( (i + 1) % 16 == 0 )
                printf("\n");
        }
        printf("\n\n");
    }
}

/*
=======================================================================================================================
下面是检测扫描攻击和异常数据包的函数
=======================================================================================================================
 */
static void my_nids_syslog(int type, int errnum, struct ip_header *iph, void *data)
{
    static int scan_number = 0;
    char source_ip[20];
    char destination_ip[20];
    char string_content[1024];
    struct host *host_information;
    unsigned char flagsand = 255, flagsor = 0;
    int i;
    char content[1024];
    switch (type) /* 检测类型 */
    {
        case NIDS_WARN_IP:
            if (errnum != NIDS_WARN_IP_HDR)
            {
                strcpy(source_ip, inet_ntoa(*((struct in_addr*) &(iph->ip_src.s_addr))));
                strcpy(destination_ip, inet_ntoa(*((struct in_addr*) &(iph->ip_dst.s_addr))));
                printf("%s,packet(apparently from %s to %s\n", nids_warnings[errnum], source_ip, destination_ip);
            }
            else
            {
                printf("%s\n", nids_warnings[errnum]);
                break;
            }
        case NIDS_WARN_TCP:
            strcpy(source_ip, inet_ntoa(*((struct in_addr*) &(iph->ip_src.s_addr))));
            strcpy(destination_ip, inet_ntoa(*((struct in_addr*) &(iph->ip_dst.s_addr))));
            if (errnum != NIDS_WARN_TCP_HDR)
            {
                printf("%s,from %s:%hi to  %s:%hi\n", nids_warnings[errnum], source_ip, ntohs(((struct tcp_header0*)data)->th_sport), destination_ip, ntohs(((struct tcphdr*)data)->th_dport));
            }
            else
            {
                printf("%s,from %s to %s\n", nids_warnings[errnum], source_ip, destination_ip);
            }
            break;
        case NIDS_WARN_SCAN:
            scan_number++;
            FILE *file = fopen("/home/higherthandeer/CLionProjects/netSecurity/log/attack_log.txt", "a");
            if (file == NULL) {
                printf("打开文件错误\n");
                return;
            }
            sprintf(string_content, "-------------  %d  -------------\n", scan_number);
            printf("%s", string_content);
            fprintf(file, "%s", string_content);
            printf("-----  发现扫描攻击 -----\n");
            fprintf(file, "%s", "-----  发现扫描攻击 -----\n");
            host_information = (struct host*)data;
            sprintf(string_content, "扫描者的IP地址为:\n");
            printf("%s", string_content);
            fprintf(file, "%s", string_content);
            sprintf(string_content, "%s\n", inet_ntoa(*((struct in_addr*) &(host_information->addr))));
            printf("%s", string_content);
            fprintf(file, "%s", string_content);
            sprintf(string_content, "被扫描者的IP地址和端口号为:\n");
            printf("%s", string_content);
            fprintf(file, "%s", string_content);
            sprintf(string_content, "");
            for (i = 0; i < host_information->n_packets; i++)
            {
                strcat(string_content, inet_ntoa(*((struct in_addr*) &(host_information->packets[i].addr))));
                sprintf(string_content + strlen(string_content), ":%hi\n", host_information->packets[i].port);
                flagsand &= host_information->packets[i].flags;
                flagsor |= host_information->packets[i].flags;
            }
            printf("%s", string_content);
            fprintf(file, "%s", string_content);
            sprintf(string_content, "");
            if (flagsand == flagsor)
            {
                i = flagsand;
                switch (flagsand)
                {
                    case 2:
                        strcat(string_content, "扫描类型为: SYN\n");
                        break;
                    case 0:
                        strcat(string_content, "扫描类型为: NULL\n");
                        break;
                    case 1:
                        strcat(string_content, "扫描类型为: FIN\n");
                        break;
                    default:
                        sprintf(string_content + strlen(string_content), "标志=0x%x\n", i);
                        fprintf(file, "%s", string_content);
                        fclose(file);
                }
            }
            else
            {
                strcat(string_content, "标志异常\n");
            }
            printf("%s", string_content);
            fprintf(file, "%s", string_content);
            fclose(file);
            break;
        default:
            sprintf(content, "未知");
            printf("%s", string_content);
            break;
    }
}

void filter_function(){
    char *device="eth0";
    char errbuf[1024];
    pcap_t *phandle;

    bpf_u_int32 ipaddress,ipmask;
    struct bpf_program fcode;
    int datalink;

    if((device=pcap_lookupdev(errbuf))==NULL){
        perror(errbuf);
        return ;
    }
    else
        printf("设备端口: %s\n",device);

    phandle=pcap_open_live(device,200,0,500,errbuf);
    if(phandle==NULL){
        perror(errbuf);
        return ;
    }

    if(pcap_lookupnet(device,&ipaddress,&ipmask,errbuf)==-1){
        perror(errbuf);
        return ;
    }
    else{
        char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];
        if(inet_ntop(AF_INET,&ipaddress,ip,sizeof(ip))==NULL)
            perror("inet_ntop error");
        else if(inet_ntop(AF_INET,&ipmask,mask,sizeof(mask))==NULL)
            perror("inet_ntop error");
        printf("IP 地址: %s, 网络掩码: %s\n",ip,mask);
    }

    int flag=1;
    while(flag){
        //input the design filter
        printf("请按照BPF机制输入过滤规则: ");
        char filterString[1024];
        if (fgets(filterString, sizeof(filterString), stdin) == NULL) {
            fprintf(stderr, "过滤规则输入错误\n");
            return ;
        }
        if(pcap_compile(phandle,&fcode,filterString,0,ipmask)==-1)
            fprintf(stderr,"pcap_compile: %s,please input again....\n",pcap_geterr(phandle));
        else
            flag=0;
    }

    if(pcap_setfilter(phandle,&fcode)==-1){
        fprintf(stderr,"pcap_setfilter: %s\n",pcap_geterr(phandle));
        return ;
    }

    if((datalink=pcap_datalink(phandle))==-1){
        fprintf(stderr,"pcap_datalink: %s\n",pcap_geterr(phandle));
        return ;
    }

    printf("datalink= %d\n",datalink);

    pcap_loop(phandle,-1,pcap_handle,NULL);
}

void detect_attack(){
   // 注册检测攻击的函数
    nids_params.syslog = my_nids_syslog;
    // 仅捕获ip数据包
    nids_params.pcap_filter = "ip";
    if (!nids_init())
        /* Libnids初始化 */
    {
        printf("出现错误：%s\n", nids_errbuf);
        exit(1);
    }
    // 循环捕获数据包
    nids_run();
    return;

}

// 抓捕ttp函数
void filter_http(){
    // 初始化nids
    nids_params.pcap_filter = "tcp port 80"; //只捕获端口80即http
    int p=0;
    //creat ac tree
    root=Create_acTrie(pattern,p);
    //creat failed pointer
    Create_failPoint(root);
    init_hashlist(http_hashList);//初始化哈希表
    dq=(data_queue *)malloc(sizeof(data_queue));
    init_queue(dq); //初始化http队列
    struct nids_chksum_ctl temp;
    temp.netaddr = 0;
    temp.mask = 0;
    temp.action = 1;
    nids_register_chksum_ctl(&temp,1);
    if(!nids_init())        //libnids初始化
    {
        printf("出现错误：%s\n",nids_errbuf);
        exit(1);
    }
    nids_register_tcp(http_protocol_callback);      //注册回调函数
    nids_run();

    Release_acTrie(root);
}


int main(int argc, char **argv)
{
    int chioce = 10;

    printf("***********************************\n");
    printf("** 欢迎进入网络空间安全信息审计系统！**\n");
    printf("***********************************\n\n");

    printf("请选择以下功能：\n");
    printf("  1. 过滤\n");
    printf("  2. Http数据包捕获与还原\n");
    printf("  3. 安全审计\n");
    printf("  0. 退出\n\n");

    printf("请输入您的选择：");
    scanf("%d", &chioce);
    getchar();  // 接收回车
    if(chioce == 1){
        filter_function();
    }else if(chioce == 2){
        filter_http();

    }else if(chioce == 3){
        detect_attack();
    }
    return 0;
}