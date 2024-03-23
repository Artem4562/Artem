#ifndef HELL_H
#define HELL_H
#include <pcap.h>
#include <vector>
#include <string>
#include <chrono>

#define  LEN_ETHERNET_ADDR  6           //lenght of MAC adress

typedef struct {
    unsigned char Destination[6];
    unsigned char Source[6];
    unsigned short Type; 
    unsigned short AppID; 
    unsigned short Lenght; 
    unsigned short Res1; 
    unsigned short Res2; 
    unsigned char noAsdu = 0;
    std::vector<char> svID;
    unsigned short smpCnt;
    unsigned long confRef;
    unsigned char smpSynch;
    int Ia;
    int Ib;
    int Ic;
    int In;
    int Ua;
    int Ub;
    int Uc;
    int Un;
}SV_PROT;

typedef struct SV_PROT_NF_I{
    private:
    std::chrono::system_clock::time_point saved_time = std::chrono::system_clock::now();
    public:
    std::string Destination = "";
    std::string Source = "";
    unsigned short AppID = 0;
    std::vector<char>svID = {};
    unsigned char id = 0;
    bool opened = false;
    std::string condition = "";
    int smt_counter = 0;
    

    // SV_PROT_NF_I(   unsigned char PDestination[6], unsigned char PSource[6], 
    //                 unsigned short PAppID, std::vector<char>PsvID, unsigned char Pid, 
    //                 bool Popened, std::string Pcondition, int Psmt_counter)
    // {
    //     for(int i = 0;i<6;i++){
    //         Destination+= std::to_string(PDestination[i]);
    //         Source+= std::to_string(PSource[i]);
    //         if(i<5){
    //             Destination+= ":";
    //             Source+= ":";
    //         }
    //     }
    //     AppID = PAppID;
    //     // std::copy(PsvID.begin(), PsvID.end(), svID.begin());
        
    //     id = u_char(Pid);
    //     opened = Popened;
    //     condition = Pcondition;
    //     smt_counter = Psmt_counter;
    // }

    // SV_PROT_NF_I(): SV_PROT_NF_I({},{},0,{},0,0,"",0){     };
    // SV_PROT_NF_I(   unsigned char PDestination[6], unsigned char PSource[6], 
    //                 unsigned short PAppID, std::vector<char>PsvID, int Pid)
    //                 :SV_PROT_NF_I(  PDestination, PSource, 
    //                                 PAppID, PsvID,Pid, 
    //                                 opened, condition,0){     };
    // SV_PROT_NF_I(   std::string Pcondition)
    //                 :SV_PROT_NF_I(  {}, {}, 
    //                                 AppID, svID,id, 
    //                                 opened, Pcondition,0){     };
    // SV_PROT_NF_I(   int Psmt_counter)
    //                 :SV_PROT_NF_I(  {}, {}, 
    //                                 AppID, svID,id, 
    //                                 opened, condition,Psmt_counter){     };

    

    bool check_time(){
        if(saved_time + std::chrono::seconds(1)  <= std::chrono::system_clock::now()){
            saved_time+=std::chrono::seconds(1);
            return 1;
        };
        return 0;
    }

    

}SV_PROT_NF_I;





void WildFox(const u_char * ,const pcap_pkthdr * , SV_PROT *);


#endif // HELL_H