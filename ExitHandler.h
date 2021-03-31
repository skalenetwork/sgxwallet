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
        ec_compute_snapshot_error = 197,  // snapshot computation error
        ec_rotation_complete = 0,         // must be zero, exit requested after rotation complete
        ec_consensus_terminate_request = 198,  // exit requested by consensus
        ec_web3_request = 199,                 // programmatic shutdown via Web3 call, when enabled
        ec_state_root_mismatch = 200,  // current state root is not equal to arrived from consensus
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
