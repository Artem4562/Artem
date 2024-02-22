#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <queue>



typedef struct {
    std::string svid;
    std::string appid;
    int Ia;
    int Ib;
} sv_stream_info;

typedef struct {
    int count=0;
    pthread_mutex_t mutex;
    std::string text;
    std::queue<sv_stream_info> sv_streams;
} data_t;

void * receive(void * external_data){
    data_t* extd = (data_t*) external_data;
    fprintf(stdout, "From thread receive: %d\n", extd->count);
    useconds_t timout = 100;
    for (;;){

        pthread_mutex_lock(&(extd->mutex));
        usleep(timout);
        extd->count++;
        extd->text = "receive";
        if (extd->count%100 == 0){
            printf("Increased from %s\n", extd->text.c_str());
        }
        pthread_mutex_unlock(&(extd->mutex));
        usleep(timout);
    }
}

void * draw(void* external_data){
    data_t* extd = (data_t*) external_data;
    fprintf(stdout, "From thread draw: %d\n", extd->count);
    useconds_t timout = 100;
    for (;;){
        
        pthread_mutex_lock(&(extd->mutex));
        usleep(timout);
        extd->count++;
        extd->text = "draw";
        if (extd->count%100 == 0){
            printf("Increased from %s\n", extd->text.c_str());
        }
        pthread_mutex_unlock(&(extd->mutex));
        usleep(timout);
        
    }
}



int main(){
    pthread_t sv_receive, draw_graphics;
    data_t data;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    data.mutex = mutex;

    pthread_create(&sv_receive, NULL, *receive, (void *) &data);
    pthread_create(&draw_graphics, NULL, *draw, (void *) &data);
    pthread_join(sv_receive, NULL);
    pthread_join(draw_graphics, NULL);
}