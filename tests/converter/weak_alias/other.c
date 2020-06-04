void say_hello() {
    // even though greetings is an alias for a static function (i.e. hello) 
    // it can still be called from outside its compilation unit. musl's libc
    // depends on this fact, for example
    greetings();
}
