#ifndef DFT_H
#define DFT_H
#include <vector>
#include <complex>
#include <iostream>
#include "hell.hpp"



#define STANDART    0   //4000 packets
#define STANDART_MP 1   //4000 packest whith garmonics that has at least 0.1% impact
#define LOWPERF     2   //4000 packets
#define LOWPERF_MP  3   //800 packest whith garmonics that has at least 0.1% impact

using namespace std::complex_literals;

typedef struct POLAR_COMPLEX {
    double NORM;
    double ANGLE;
    POLAR_COMPLEX(double P_NORM = 0, double P_ANGLE = 0){
        NORM = P_NORM;
        ANGLE = P_ANGLE;
    }
    // POLAR_COMPLEX():POLAR_COMPLEX(0.0,0.0){
    // };
   
}POLAR_COMPLEX;

typedef struct SV_PROT_D {
    POLAR_COMPLEX Ia;
    POLAR_COMPLEX Ib;
    POLAR_COMPLEX Ic;
    POLAR_COMPLEX In;
    POLAR_COMPLEX Ua;
    POLAR_COMPLEX Ub;
    POLAR_COMPLEX Uc;
    POLAR_COMPLEX Un;
    int FREC;

    SV_PROT_D(  POLAR_COMPLEX PIa , POLAR_COMPLEX PIb , POLAR_COMPLEX PIc , POLAR_COMPLEX PIn ,
                POLAR_COMPLEX PUa , POLAR_COMPLEX PUb , POLAR_COMPLEX PUc , POLAR_COMPLEX PUn , int PFREC  )
    {
        Ia = PIa;
        Ib = PIb;
        Ic = PIc;
        In = PIn;
        Ua = PUa;
        Ub = PUb;
        Uc = PUc;
        Un = PUn;
        FREC = PFREC;
    };

    SV_PROT_D(): SV_PROT_D ({0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},0){    };
    SV_PROT_D(int PFREC): SV_PROT_D({0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},PFREC){    }; 


    
}SV_PROT_D;



typedef struct SV_PROT_AMP{
    
    public:
    std::vector<int> Ia;
    std::vector<int> Ib;
    std::vector<int> Ic;
    std::vector<int> In;
    std::vector<int> Ua;
    std::vector<int> Ub;
    std::vector<int> Uc;
    std::vector<int> Un;
    

    SV_PROT_D DTF(int N, int K, int FREC){
        SV_PROT_D COCO {    DFT_I(N,Ia,K),DFT_I(N,Ib,K),DFT_I(N,Ic,K),DFT_I(N,In,K),
                            DFT_I(N,Ua,K),DFT_I(N,Ub,K),DFT_I(N,Uc,K),DFT_I(N,Un,K), FREC};
        return COCO;
    }

    SV_PROT_AMP push_back_prot(SV_PROT Prot)
    {
        this->Ia.push_back(Prot.Ia);
        this->Ib.push_back(Prot.In);
        this->Ic.push_back(Prot.Ic);
        this->In.push_back(Prot.In);
        this->Ua.push_back(Prot.Ua);
        this->Ub.push_back(Prot.Ub);
        this->Uc.push_back(Prot.Uc);
        this->Un.push_back(Prot.Un);
        return *this;
    };

    SV_PROT_AMP erase_prot_all()
    {
        this->Ia.erase(this->Ia.cbegin(),this->Ia.cend());
        this->Ib.erase(this->Ib.cbegin(),this->Ib.cend());
        this->Ic.erase(this->Ic.cbegin(),this->Ic.cend());
        this->In.erase(this->In.cbegin(),this->In.cend());
        this->Ua.erase(this->Ua.cbegin(),this->Ua.cend());
        this->Ub.erase(this->Ub.cbegin(),this->Ub.cend());
        this->Uc.erase(this->Uc.cbegin(),this->Uc.cend());
        this->Un.erase(this->Un.cbegin(),this->Un.cend());
        return *this;
    };

    // SV_PROT_AMP()
    // {
    //     Ia = {};
    //     Ib = {};
    //     Ic = {};
    //     In = {};
    //     Ua = {};
    //     Ub = {};
    //     Uc = {};
    //     Un = {};
    // }

    POLAR_COMPLEX DFT_I(int N, std::vector<int> argv, int K){
        std::complex<double> PR = 0.0 +0.0i;
        for (int n = 0; n < N; n++){
                PR+=(double)argv[n]*exp((-2*M_PI*n*K/N)*1i);
            };
        return {abs(PR)/(N/2*sqrt(2)),arg(PR)*180/M_PI+180};
    }

    



}SV_PROT_AMP;

int DFT_4000D_1S (int, SV_PROT_AMP, int , std::vector<SV_PROT_D> *);


#endif // HELL_H