"""
Param Optimizer Composite Program
Runs all the param optimizers made.
"""
from Benchmark_Normal_Sphincs.run_all import run as sphincs_run
from Benchmark_Sphincs_Alpha.run_all import run as sphincs_alpha_run
from Benchmark_SphincsC.run_all import run as sphincs_c_run
from Benchmark_DGSP_Normal.DGSP_no_server.run_all import run as sphincs_dgsp_serverless_run
from Benchmark_DGSP_Normal.DGSP_with_server.run_all import run as sphincs_dgsp_server_run
from Benchmark_DGSP_Alpha.DGSP_no_server_alpha.run_all import run as sphincs_dgsp_alpha_serverless_run
from Benchmark_DGSP_Alpha.DGSP_with_server_alpha.run_all import run as sphincs_dgsp_alpha_server_run
from Benchmark_DGSP_C.DGSP_no_server_C.run_all import run as sphincs_dgsp_c_serverless_run
from Benchmark_DGSP_C.DGSP_with_server_C.run_all import run as sphincs_dgsp_c_server_run
# uncomment below if on unix to limit mem usage
import resource

# uncomment below if on unix to limit memory usage.
def set_memory_limits():
    limit = int(4 * 1024 ** 3)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except AttributeError:
        print("  WARNING: resource.setrlimit not available on this OS (non-Linux)")
    except ValueError as e:
        print(f"  WARNING: could not set memory limit: {e}")

"""
Yeah it just calls their mains to do it essentially.
Also, depending on your spec, this does take time.
"""
if __name__ == "__main__":
    # uncomment below if on unix to limit memory usage.
    set_memory_limits()
    sphincs_run()
    sphincs_alpha_run()
    sphincs_dgsp_serverless_run()
    sphincs_dgsp_server_run()
    sphincs_dgsp_alpha_serverless_run()
    sphincs_dgsp_alpha_server_run()
    # last cuz it takes the longest
    sphincs_c_run()
    sphincs_dgsp_c_serverless_run()
    sphincs_dgsp_c_server_run()

