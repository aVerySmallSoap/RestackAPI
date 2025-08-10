import subprocess
import time

target = "http://www.public-firing-range.appspot.com/"
results = []
run_count = 0

# default
while run_count < 10:
    start = time.perf_counter()
    process = subprocess.Popen(["wapiti", "--flush-session","-u", target])
    process.wait()
    end = time.perf_counter()
    results.append(end - start)
    run_count += 1

print(results)