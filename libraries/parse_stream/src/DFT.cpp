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

int MODE (int N, int* N_L){
    if (range<LEN_P,2*LEN_P>::contains(N)){
        *N_L = LEN_P;
        return 0;
    }
    if (range<LEN_P_2,LEN_P>::contains(N)) {
        *N_L = LEN_P_2;
        return 0;
    }
    if (range<LEN_P_5,LEN_P_2>::contains(N)){
        *N_L = LEN_P_5;
        return 0;
    }
    if (range<LEN_P_10,LEN_P_5>::contains(N)) {
        *N_L = LEN_P_10;
        return 0;
    }
    return -1;
}



int DFT_4000D_1S (int N, SV_PROT_AMP IN, int FLAG = LOWPERF, std::vector<SV_PROT_D> *OUT = 0){
    int N_L;
    int K;
    bool MP;

    if(MODE(N,&N_L)){
        return -1;
    };
    
    

    switch (FLAG)
    {
    case STANDART:
        K=50*(float(N_L)/LEN_P);
        MP=false;
        break;
    case STANDART_MP:
        K=50*(float(N_L)/LEN_P);
        MP=true;
        break;
    case LOWPERF:
        K=50*(float(N_L)/LEN_P);
        MP=false;
        break;
    case LOWPERF_MP:
        K=50*(float(N_L)/LEN_P);
        MP=true;
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
        OUT->push_back(IN.DTF(N_L,K, K/(float(N_L)/LEN_P)));
        break;
    }
    }
    return 0;
}

