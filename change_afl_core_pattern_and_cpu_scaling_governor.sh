#!/bin/bash

[ "$UID" -eq 0 ] || exec sudo bash "$0" "$@"
echo "echo core | tee /proc/sys/kernel/core_pattern"
echo core | tee /proc/sys/kernel/core_pattern > /dev/null

echo "echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null

echo "*******************************************************"

echo "/proc/sys/kernel/core_pattern: [$(cat /proc/sys/kernel/core_pattern)]"

for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo "$f: [$(cat ${f})]"
done
