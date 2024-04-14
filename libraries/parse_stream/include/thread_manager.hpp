#include "DFT.hpp"
#include <queue>
#include <functional>


#define GLFW_INCLUDE_NONE
#define GLAD_GL_IMPLEMENTATION
#define _USE_MATH_DEFINES
#define LINE_LEN 16

//codes of commands passing to manager functions
//--------------------------------------------------
#define SV_open 1000
#define SV_close 1001
#define Window_close 1100
#define Exit 9999
//--------------------------------------------------




//struct that are passed beatween threads
//--------------------------------------------------
typedef struct command_manager {
    pthread_mutex_t mutex_CM;
    std::queue<int> command_queue;
    pthread_mutex_t mutex_DK;
    
    pcap_t *fp;
    private:
    int N;
    public:
    int* Errno = &N;
    
    private:
    std::vector<SV_PROT_NF_I>  DataKrat_T;
    std::vector<std::vector<SV_PROT_D>>  DataFull_T;
    

    public:
    std::vector<SV_PROT_NF_I> * DataKrat = &DataKrat_T;
    std::vector<std::vector<SV_PROT_D>> * DataFull = &DataFull_T;
    void sv_innit(pthread_mutex_t mutex){
        pthread_mutex_lock(&mutex);
        DataKrat = &DataKrat_T;
        DataFull = &DataFull_T;
        pthread_mutex_unlock(&mutex);

    }



}command_manager;
//--------------------------------------------------


//struct that are preparatinion for config file
//--------------------------------------------------
typedef struct conf_pr{
    std::string name;
    std::string value;

}conf_pr;
//--------------------------------------------------


//struct that helps shift sin to 0
//--------------------------------------------------
typedef struct shiftUA{
    int MinUa = 0;
    bool flg,fg,flag = false;
}shiftUA;
//--------------------------------------------------


//very IMPORNTANT CODE, don't know how it's work but it's the only thing that do
// UNDER ANY sirmconstances DO NOT DELETE!!!
//--------------------------------------------------------------------------------

template <typename T> struct Callback;

template <typename Ret, typename... Params>
struct Callback<Ret(Params...)> {
   template <typename... Args> 
   static Ret callback(Args... args) {                    
      return func(args...);  
   }
   static std::function<Ret(Params...)> func; 
};

template <typename Ret, typename... Params> std::function<Ret(Params...)> Callback<Ret(Params...)>::func;





typedef void (*callback_t)(u_char *, const struct pcap_pkthdr *, const u_char *);
//---------------------------------------------------------------------------------

//defenishions for threads
//--------------------------------------------------
void *draw(void *);
void *receive(void *);
void *manager(void *);
void *loop_breaker(void *);
void *alarm_for_prot(void *);
//--------------------------------------------------

//defenishions for functions
//--------------------------------------------------
void config_writer(conf_pr );
//--------------------------------------------------