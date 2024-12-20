#!/usr/bin/python3

import subprocess
import time

TESTER             = 'cube1@130.192.225.61'
IFNAME             = 'ens1f0'
MOONGEN_PATH       = '~/Federico/MoonGen/build/MoonGen'
APP_NAME           = 'xdpsock_user'
APP_PATH           = f'/home/polycube/src/af_xdp-tests/{APP_NAME}'
PKTGEN_SCRIPT_PATH = '/home/cube1/Federico/MoonGen/examples/test-rss.lua'
RES_FILENAME       = 'res-redirect-macswap.csv'
RUNS               = 5
TRIAL_TIME         = 10  # Seconds of a single test trial
FINAL_TRIAL_TIME   = 30
TESTS_GAP          = 5   # Seconds of gap between two tests
MODES              = ['xdp', 'af_xdp', 'af_xdp-bp', 'af_xdp-poll', 'combined',
                      'combined-bp', 'combined-poll']
FLAGS              = {
                      'xdp': ['-M', 'XDP'],
                      'af_xdp': [],
                      'af_xdp-bp': ['-B'],
                      'af_xdp-poll': ['-p'],
                      'combined': ['-M', 'COMBINED'],
                      'combined-bp': ['-M', 'COMBINED', '-B'],
                      'combined-poll': ['-M', 'COMBINED', '-p']
                     }
MAX_TARGET         = 10000
TARGET_STEP        = 50
MAX_LOSS           = 0.001
PERF_COUNTERS      = ['LLC-loads', 'LLC-load-misses', 'LLC-stores',
                      'LLC-store-misses']

def round_target(target):
    return int(target / TARGET_STEP) * TARGET_STEP

def get_pktgen_stats():
    cmd = ['scp', f'{TESTER}:./tmp.csv' , '.']
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    f = open("tmp.csv", "r")
    ret = f.read().splitlines()[1].split(';')
    f.close()
    return ret[2], int(ret[1]), int(ret[3])

out = open(RES_FILENAME, 'w')
out.write("run;mode;throughput;target;llc-loads;llc-load-misses;llc-store;llc-store-misses;user;system;softirq;verified\n")

for run in range(RUNS):
    for mode in MODES:
        print(f'Run {run}: measuring mode {mode}...')

        if mode == 'af_xdp-bp' or mode == 'combined-bp':
            # Enable busy polling
            cmd = ['sudo', 'tee',
                    f'/sys/class/net/{IFNAME}/napi_defer_hard_irqs']
            subprocess.run(cmd, check=True, text=True, input='2',
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cmd = ['sudo', 'tee',
                    f'/sys/class/net/{IFNAME}/gro_flush_timeout']
            subprocess.run(cmd, check=True,  text=True, input='200000', 
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cmd = ['taskset', '1', 'sudo', APP_PATH, '-i', IFNAME] + FLAGS[mode] \
                + ['--', '-q']
        app = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
               stderr=subprocess.DEVNULL)

        max_t = MAX_TARGET
        min_t = 0
        curr_t = MAX_TARGET
        best_t = 0
        best_r = 0

        while max_t - min_t > TARGET_STEP:
            print(f'Target {curr_t} Mbps')

            cmd = ['ssh', TESTER, 'sudo', MOONGEN_PATH, PKTGEN_SCRIPT_PATH, '0',
                    '0', '-c', '6', '-o', 'tmp.csv', '-r', str(curr_t), '-t',
                    str(TRIAL_TIME)]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)      

            rate, tx_pkts, rx_pkts = get_pktgen_stats()
            loss = (tx_pkts - rx_pkts) / tx_pkts
            print(f'Sent {tx_pkts}, received {rx_pkts}, rate {rate} Mpps, loss {(loss*100):.2f}%')

            if loss <= MAX_LOSS:
                best_t = curr_t
                best_r = rate
                min_t = curr_t
            else:
                max_t = curr_t

            curr_t = round_target((max_t + min_t) / 2)

        # Perform the cache run
        print('Checking result, cache and CPU...')

        cmd = ['ssh', TESTER, 'sudo', MOONGEN_PATH, PKTGEN_SCRIPT_PATH, '0',
                    '0', '-c', '6', '-o', 'tmp.csv', '-r', str(best_t), '-t',
                    str(FINAL_TRIAL_TIME)]
        pktgen = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)

        time.sleep(5)

        # Collect cache statistics
        cmd = ['sudo', 'perf', 'stat', '-C', '0', '--no-big-num', '-e',
                ','.join(PERF_COUNTERS), '-r', '10', 'sleep', '1']
        res = subprocess.run(cmd, check=True, capture_output=True, text=True) \
                .stderr
        reslines = res.splitlines()
        loads        = reslines[3].split()[0]
        load_misses  = reslines[4].split()[0]
        stores       = reslines[5].split()[0]
        store_misses = reslines[6].split()[0]

        # Collect CPU statistics
        cmd = ['sar', '-P', '0', '-u', 'ALL', '10', '1']
        res = subprocess.run(cmd, check=True, capture_output=True, text=True) \
                .stdout
        resline = res.splitlines()[3]
        user = resline.split()[3]
        system = resline.split()[5]
        softirq = resline.split()[9]

        pktgen.wait()

        rate, tx_pkts, rx_pkts = get_pktgen_stats()
        loss = (tx_pkts - rx_pkts) / tx_pkts
        if loss <= MAX_LOSS:
            verified = True
        else:
            verified = False

        out.write(f'{run};{mode};{best_r};{best_t};{loads};{load_misses};{stores};{store_misses};{user};{system};{softirq};{verified}\n')
        out.flush()

        print(f'Target {best_t} Mbps, throughput: {best_r} Mpps, {"VERIFIED" if verified else "NOT VERIFIED"}, User {user}%, System {system}%, SoftIRQ {softirq}%\n')

        cmd = ['sudo', 'killall', APP_NAME]
        subprocess.run(cmd, check=True)

        if mode == 'af_xdp-bp' or mode == 'combined-bp':
            # Disable busy polling
            cmd = ['sudo', 'tee',
                    f'/sys/class/net/{IFNAME}/napi_defer_hard_irqs']
            subprocess.run(cmd, check=True, text=True, input='0',
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cmd = ['sudo', 'tee',
                    f'/sys/class/net/{IFNAME}/gro_flush_timeout']
            subprocess.run(cmd, check=True,  text=True, input='0', 
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(TESTS_GAP)

out.close()