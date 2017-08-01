inline int inline_me(int num) {
    if (num <= 0) {
        return 1;
    }
    else {
        int ret = inline_me(num - 1) + inline_me(num - 2) + inline_me(num - 3); 
        printf("ret=%d\n", ret);
        return ret;
    }
}
