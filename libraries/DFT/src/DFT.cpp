#include <complex>
#include <cmath>
#include <vector>
#include <DFT.hpp>


using namespace std::complex_literals;

#define  LEN_P       4000  //Standart lenght of 1 sec of packets, gives 1 HZ accuracy very high performance lost
#define  LEN_P_2     2000  //Half of lenght of 1 sec of packets switches automatically when there less then 4K packets, gives 2 HZ accuracy
#define  LEN_P_5     800   //Mode that could provide informatinion even whith packets lost, gives 5 HZ accuracy
#define  LEN_P_10    400   //Minimal lenght of 0.2 sec of packets, gives 10 HZ accuracy

POLAR_COMPLEX DTF(int N, std::vector<int> IN, int K){
    std::complex<double> PR = 0.0 +0.0i;
    POLAR_COMPLEX OUT;
    for (int n = 0; n < N; n++){
        PR+=(double)IN[n]*exp((-2*M_PI*n*K/N)*1i);
    };
    OUT.NORM=abs(PR)/(N/2*sqrt(2));
    OUT.ANGLE=arg(PR)*180/M_PI+180;
    return OUT;
}


int DFT_4000D_1S (int N, SV_PROT_F_I IN, int FLAG, std::vector<DATAF> *OUT){
    int N_L;
    int K;
    bool MP;
    POLAR_COMPLEX PR;
    DATAF SES;
    if(N>=LEN_P) N_L=N;
    else if(N>=LEN_P_2) N_L=LEN_P_2;
    else if(N>=LEN_P_5) N_L=LEN_P_5;
    else if(N>=LEN_P_10) N_L=LEN_P_10;
    else if(N<LEN_P_10) return -3;

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
    }

    
    switch (MP)
    {
    // case true:
    // {
    //     POLAR_COMPLEX PIA, PIB, PIC, PIN, PUA, PUB, PUC, PUN;
    //     DTF(N_L,IN.Ia,&((*OUT)[0].Ia),K);
    //     DTF(N_L,IN.Ib,&((*OUT)[0].Ib),K);
    //     DTF(N_L,IN.Ic,&((*OUT)[0].Ic),K);
    //     DTF(N_L,IN.In,&((*OUT)[0].In),K);
    //     DTF(N_L,IN.Ua,&((*OUT)[0].Ua),K);
    //     DTF(N_L,IN.Ub,&((*OUT)[0].Ub),K);
    //     DTF(N_L,IN.Uc,&((*OUT)[0].Uc),K);
    //     DTF(N_L,IN.Un,&((*OUT)[0].Un),K);
    //     for(int i = K+1; i<=N_L;i++){
    //         DTF(N_L,IN.Ia,&PIA,K);
    //         DTF(N_L,IN.Ib,&PIB,K);
    //         DTF(N_L,IN.Ic,&PIC,K);
    //         DTF(N_L,IN.In,&PIN,K);
    //         DTF(N_L,IN.Ua,&PUA,K);
    //         DTF(N_L,IN.Ub,&PUB,K);
    //         DTF(N_L,IN.Uc,&PUC,K);
    //         DTF(N_L,IN.Un,&PUN,K);
    //         if(0.001>=PIA.NORM/(*OUT)[0].Ia.NORM || 0.001>=PIB.NORM/(*OUT)[0].Ib.NORM || 0.001>=PIC.NORM/(*OUT)[0].Ic.NORM || 0.001>=PIN.NORM/(*OUT)[0].In.NORM
    //         || 0.001>=PUA.NORM/(*OUT)[0].Ua.NORM || 0.001>=PUB.NORM/(*OUT)[0].Ub.NORM || 0.001>=PUC.NORM/(*OUT)[0].Uc.NORM || 0.001>=PUN.NORM/(*OUT)[0].Un.NORM)
    //         {
    //             DATAF Per;
    //             Per.Ia=PIA;
    //             Per.Ib=PIB;
    //             Per.Ic=PIC;
    //             Per.In=PIN;
    //             Per.Ua=PUA;
    //             Per.Ub=PUB;
    //             Per.Uc=PUC;
    //             Per.Un=PUN;
    //             Per.FREC=K/(N_L/LEN_P);
    //             (*OUT).push_back(Per);
    //         }
    //     }
    //     break;
    // }  
        
    case false:
    {
        SES.Ia =DTF(N_L,IN.Ia,K);
        SES.Ib =DTF(N_L,IN.Ib,K);
        SES.Ic =DTF(N_L,IN.Ic,K);
        SES.In =DTF(N_L,IN.In,K);
        SES.Ua =DTF(N_L,IN.Ua,K);
        SES.Ub =DTF(N_L,IN.Ub,K);
        SES.Uc =DTF(N_L,IN.Uc,K);
        SES.Un =DTF(N_L,IN.Un,K);
        break;
    }
    }
    OUT->push_back(SES);
    return 0;
}

