#ifndef EXITHANDLER_H
#define EXITHANDLER_H

#include <signal.h>

class ExitHandler {
public:
    enum exit_code_t {
        ec_success = 0,
        ec_initing_user_space = 202,  // error or exception while initializing user space
    };

private:
    static volatile bool s_shouldExit;
    static volatile int m_signal;
    static volatile exit_code_t g_ec;

    ExitHandler() = delete;

public:
    static void exitHandler( int s );
    static void exitHandler( int s, ExitHandler::exit_code_t ec );
    static bool shouldExit() { return s_shouldExit; }
    static int getSignal() { return m_signal; }
    static exit_code_t requestedExitCode() { return g_ec; }

};

#endif // EXITHANDLER_H
