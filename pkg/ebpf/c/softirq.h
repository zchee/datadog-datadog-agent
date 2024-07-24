#ifndef SOFTIRQ_H
#define SOFTIRQ_H

typedef struct {
    unsigned long max_packets_processed;
    unsigned long entry_packets_count;
} ppirq_t;

#endif
