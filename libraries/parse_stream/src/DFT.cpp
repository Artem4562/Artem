#include <complex>
#include <cmath>
#include <vector>
#include <DFT.hpp>


using namespace std::complex_literals;

#define  LEN_P       4000  //Standart lenght of 1 sec of packets, gives 1 HZ accuracy very high performance lost
#define  LEN_P_2     2000  //Half of lenght of 1 sec of packets switches automatically when there less then 4K packets, gives 2 HZ accuracy
#define  LEN_P_5     800   //Mode that could provide informatinion even whith packets lost, gives 5 HZ accuracy
#define  LEN_P_10    400   //Minimal lenght of 0.2 sec of packets, gives 10 HZ accuracy



template <int min, int max> class range {
    public:
    static bool contains(int i) { return min <= i  && i < max; } 
};





int DFT_4000D_1S_800P ( SV_PROT_AMP * IN, int FLAG = LOWPERF, std::vector<SV_PROT_D> *OUT = 0){
    const int N_L = 4000;
    int K;
    bool MP, perf;

    
    

    switch (FLAG)
    {
    case STANDART:
        K = 50 * (float(N_L)/LEN_P);
        MP = false;
        perf = true;
        break;
    case STANDART_MP:
        K = 50 * (float(N_L)/LEN_P);
        MP = true;
        perf = true;
        break;
    case LOWPERF:
        K = 50 * (float(N_L)/LEN_P);
        MP = false;
        perf = false;
        break;
    case LOWPERF_MP:
        K = 50 * (float(N_L)/LEN_P);
        MP = false;
        break;
    default:
        return -2;
    }

    
    switch (MP)
    {
    // case true:
    // {
    //     
    //     break;
    // }  
        
    case false:
    {
        if(IN->queue_number == 4) OUT->push_back(IN->DTF_FC(K, K/(float(N_L)/LEN_P)));
        else IN->DTF_FC(K, K/(float(N_L)/LEN_P));
        break;
    }
    }
    return 0;
}

