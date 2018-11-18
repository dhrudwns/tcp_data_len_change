#ifndef FLOWMANAGE_H
#define FLOWMANAGE_H
#include <stdint.h>

class flowmanage
{
public:
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t sport;
    uint16_t dport;
    flowmanage(const uint32_t &ip_src, const uint32_t &ip_dst, const uint16_t &sport, const uint16_t &dport)
    {
        this->ip_src = ip_src;
        this->ip_dst = ip_dst;
        this->sport = sport;
        this->dport = dport;
    }

    void init(const uint32_t &ip_src, const uint32_t &ip_dst, const uint16_t &sport, const uint16_t &dport)
    {
        this->ip_src = ip_src;
        this->ip_dst = ip_dst;
        this->sport = sport;
        this->dport = dport;
    }

    void reverse(flowmanage flow)
    {
        this->ip_src = flow.ip_dst;
        this->ip_dst = flow.ip_src;
        this->sport = flow.dport;
        this->dport = flow.sport;
    }

    bool operator < (const flowmanage &flow) const {
                          if(this->ip_src < flow.ip_src) return true;
                          if(this->ip_src > flow.ip_src) return false;
                          if(this->ip_dst < flow.ip_dst) return true;
                          if(this->ip_dst > flow.ip_dst) return false;
                          if(this->sport < flow.sport) return true;
                          if(this->sport > flow.sport) return false;
                          if(this->dport < flow.dport) return true;
                          else return false;
                  }

};
#endif // FLOW_H
