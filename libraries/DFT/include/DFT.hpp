#ifndef DFT_H
#define DFT_H
#include <vector>
#include <complex>


#define STANDART    0   //4000 packets
#define STANDART_MP 1   //4000 packest whith garmonics that has at least 0.1% impact
#define LOWPERF     2   //4000 packets
#define LOWPERF_MP  3   //800 packest whith garmonics that has at least 0.1% impact



typedef struct {
    double NORM;
    double ANGLE;
}POLAR_COMPLEX;

typedef struct {
    POLAR_COMPLEX Ia;
    POLAR_COMPLEX Ib;
    POLAR_COMPLEX Ic;
    POLAR_COMPLEX In;
    POLAR_COMPLEX Ua;
    POLAR_COMPLEX Ub;
    POLAR_COMPLEX Uc;
    POLAR_COMPLEX Un;
    int FREC = 50;
}DATAF;

typedef struct {
    std::vector<int> Ia;
    std::vector<int> Ib;
    std::vector<int> Ic;
    std::vector<int> In;
    std::vector<int> Ua;
    std::vector<int> Ub;
    std::vector<int> Uc;
    std::vector<int> Un;
}SV_PROT_F_I;

int DFT_4000D_1S (int, SV_PROT_F_I, int , std::vector<DATAF> *);


#endif // HELL_H