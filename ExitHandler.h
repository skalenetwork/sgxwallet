#ifndef EXITHANDLER_H
#define EXITHANDLER_H

#include <signal.h>

class ExitHandler {
public:
    enum { KILL_TIMEOUT = 57 };

    enum exit_code_t {
        ec_success = 0,
        ec_failure = 1,  // same as EXIT_FAILURE in stdlib.h, generic failure in main()
        ec_termninated_by_signal = 196,
        ec_error_starting_server = 197, // error starting one of the http(s) servers
        ec_rotation_complete = 0,         // must be zero, exit requested after rotation complete
        ec_error_creating_database = 198,  // error initing LevelDB
        ec_error_initing_sek = 199,                 // error while initing or validating SEK
        ec_creating_certificate = 200,  // error creating SSL certificate to initialize server
        ec_initing_enclave = 201,  // error starting secure enclave
        ec_initing_user_space = 202,  // error or exception while initializing user space
        ec_cannot_start_zeromq = 203,  // error starting ZMQ server
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
