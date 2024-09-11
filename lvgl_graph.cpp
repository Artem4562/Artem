#include <lvgl/lvgl.h>
#define LV_COLOR_DEPTH

void my_disp_flush(lv_display_t * disp, const lv_area_t * area, lv_color_t * color_p)
{
    int32_t x, y;
    /*It's a very slow but simple implementation.
     *`set_pixel` needs to be written by you to a set pixel on the screen*/
    for(y = area->y1; y <= area->y2; y++) {
        for(x = area->x1; x <= area->x2; x++) {
            set_pixel(x, y, *color_p);
            color_p++;
        }
    }

    lv_display_flush_ready(disp);         /* Indicate you are ready with the flushing*/
}

int main(){
    
    lv_init();
    lv_display_t *display = lv_display_create(600, 800);

    /*Declare a buffer for 1/10 screen size*/
    #define BYTE_PER_PIXEL (LV_COLOR_FORMAT_GET_SIZE(LV_COLOR_FORMAT_RGB565)) /*will be 2 for RGB565 */
    static uint8_t buf1[100* 100 / 10 * BYTE_PER_PIXEL];
    lv_display_set_buffers(display, buf1, NULL, sizeof(buf1), LV_DISPLAY_RENDER_MODE_PARTIAL);  /*Initialize the display buffer.*/
    
    lv_display_set_flush_cb(display, my_disp_flush);
dsfsdf
    lv_timer_handler();
    }
