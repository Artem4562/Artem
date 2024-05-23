#ifndef DFT_H
#define DFT_H
#include <vector>
#include <complex>
#include <iostream>
#include <queue>
#include "hell.hpp"



#define STANDART    0   //4000 packets
#define STANDART_MP 1   //4000 packest whith garmonics that has at least 0.1% impact
#define LOWPERF     2   //800  packets
#define LOWPERF_MP  3   //800  packest whith garmonics that has at least 0.1% impact





using namespace std::complex_literals;



typedef struct POLAR_COMPLEX {
    double NORM;
    double ANGLE;
    POLAR_COMPLEX(double P_NORM = 0, double P_ANGLE = 0){
        NORM = P_NORM;
        ANGLE = P_ANGLE;
    }
   
}POLAR_COMPLEX;


typedef struct SV_PROT_D {
    POLAR_COMPLEX Ia = {0.0,0.0};
    POLAR_COMPLEX Ib = {0.0,0.0};
    POLAR_COMPLEX Ic = {0.0,0.0};
    POLAR_COMPLEX In = {0.0,0.0};
    POLAR_COMPLEX Ua = {0.0,0.0};
    POLAR_COMPLEX Ub = {0.0,0.0};
    POLAR_COMPLEX Uc = {0.0,0.0};
    POLAR_COMPLEX Un = {0.0,0.0};
    int FREC = 0;

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


typedef struct complex_form{
    std::complex<double> Ia = 0.0 +0.0i;
    std::complex<double> Ib = 0.0 +0.0i;
    std::complex<double> Ic = 0.0 +0.0i;
    std::complex<double> In = 0.0 +0.0i;
    std::complex<double> Ua = 0.0 +0.0i;
    std::complex<double> Ub = 0.0 +0.0i;
    std::complex<double> Uc = 0.0 +0.0i;
    std::complex<double> Un = 0.0 +0.0i;

    inline complex_form operator +=(complex_form IN){
        this->Ia + IN.Ia;
        this->Ib + IN.Ib;
        this->Ic + IN.Ic;
        this->In + IN.In;
        this->Ua + IN.Ua;
        this->Ub + IN.Ub;
        this->Uc + IN.Uc;
        this->Un + IN.Un;
        return *this;
    }

    

    void Del(){
    Ia = 0.0 +0.0i;
    Ib = 0.0 +0.0i;
    Ic = 0.0 +0.0i;
    In = 0.0 +0.0i;
    Ua = 0.0 +0.0i;
    Ub = 0.0 +0.0i;
    Uc = 0.0 +0.0i;
    Un = 0.0 +0.0i;
    }

    POLAR_COMPLEX convert(std::complex<double> IN){
        return {abs(IN)/(4000/2*sqrt(2)),arg(IN)*180/M_PI+180};
    }

}complex_form;



typedef struct SV_PROT_AMP{
    private:
    complex_form P_R;
    public:
    std::queue<int> Ia;
    std::queue<int> Ib;
    std::queue<int> Ic;
    std::queue<int> In;
    std::queue<int> Ua;
    std::queue<int> Ub;
    std::queue<int> Uc;
    std::queue<int> Un;

    int queue_number = 0;
    


    SV_PROT_AMP push_back_prot(SV_PROT Prot)
    {
        this->Ia.push(Prot.Ia);
        this->Ib.push(Prot.Ib);
        this->Ic.push(Prot.Ic);
        this->In.push(Prot.In);
        this->Ua.push(Prot.Ua);
        this->Ub.push(Prot.Ub);
        this->Uc.push(Prot.Uc);
        this->Un.push(Prot.Un);
        return *this;
    };

  
    int size()
    {
        int S = this->Ia.size();
        return S;
    }

    SV_PROT_D DTF_FC(int K, int FREC){
        int n, N;
        switch (queue_number)
        {
        case 0:
            n=0;
            N=800;
            break;
        
        case 1:
            n=800;
            N=1600;
            break;
        
        case 2:
            n=1600;
            N=2400;
            break;
        
        case 3:
            n=2400;
            N=3200;
            break;
        
        case 4:
            n=3200;
            N=4000;
            break;

        case 5:
            n=0;
            N=800;
            queue_number = 0;
            P_R.Del();
            break;

        }

        
        P_R.Ia += this->DFT_I(N,n,&this->Ia,K);
        P_R.Ib += this->DFT_I(N,n,&this->Ib,K);
        P_R.Ic += this->DFT_I(N,n,&this->Ic,K);
        P_R.In += this->DFT_I(N,n,&this->In,K);
        P_R.Ua += this->DFT_I(N,n,&this->Ua,K);
        P_R.Ub += this->DFT_I(N,n,&this->Ub,K);
        P_R.Uc += this->DFT_I(N,n,&this->Uc,K);
        P_R.Un += this->DFT_I(N,n,&this->Un,K);


        SV_PROT_D COCO {    P_R.convert(P_R.Ia),P_R.convert(P_R.Ib),P_R.convert(P_R.Ic),P_R.convert(P_R.In),
                            P_R.convert(P_R.Ua),P_R.convert(P_R.Ub),P_R.convert(P_R.Uc),P_R.convert(P_R.Un), FREC};
        queue_number++;

        return COCO;
    }


    std::complex<double> DFT_I(int N, int n, std::queue<int> * argv, int K){
        std::complex<double> PR = 0.0 +0.0i;
        

        for (; n < N; n++){
                PR+=(double) argv->front()*exp((-2*M_PI*n*K/N)*1i);
                argv->pop();
            };
        return PR;
    }

    



}SV_PROT_AMP;





int DFT_4000D_1S_800P ( SV_PROT_AMP *, int , std::vector<SV_PROT_D> *);




#endif // HELL_H