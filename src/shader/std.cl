void memcpy(void *dst, const void *src, size_t len) {
    for (size_t offset = 0; offset < len; offset++) {
        ((uchar*) dst)[offset] = ((uchar*) src)[offset];
    }
}

void memset(void *dst, uchar byte, size_t len) {
    for (size_t offset = 0; offset < len; offset++) {
        ((uchar*) dst)[offset] = byte;
    }
}

int memcmp(const void *str1, const void *str2, size_t len) {
    for (size_t offset = 0; offset < len; offset++) {
        uchar byte1 = ((uchar*) str1)[offset];
        uchar byte2 = ((uchar*) str2)[offset];

        if (byte1 != byte2) {
            return byte1 < byte2 ? -1 : 1;
        }
    }

    return 0;
}
