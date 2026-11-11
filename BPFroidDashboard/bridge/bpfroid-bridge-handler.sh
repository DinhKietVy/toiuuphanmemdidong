#!/system/bin/sh
# BPFroid bridge handler: `toybox nc -L` chạy script này một lần cho mỗi kết nối.
# Lệnh: STATUS | START | STOP | LOGS | POLL
BASE=/data/local/tmp
ENGINE=$BASE/tracee-android
LOG=$BASE/bpfroid-engine.log
RUN_ID_FILE=$BASE/bpfroid-run.id
KPROBES="pvfs_write rvfs_write pvfs_writev rvfs_writev"

engine_pid() { /system/bin/pidof tracee-android; }

status_line() {
    PID=$(engine_pid)
    [ -n "$PID" ] && echo "RUNNING:$PID" || echo "STOPPED"
}

# Tracee không gỡ kprobe khi bị dừng; nếu còn sót, START lần sau lỗi -17 (EEXIST).
# Kernel có thể chưa nhả probe ngay khi tiến trình vừa thoát (EBUSY), nên thử lại vài lần.
cleanup_kprobes() {
    for T in /sys/kernel/tracing /sys/kernel/debug/tracing; do
        [ -w "$T/kprobe_events" ] || continue
        try=0
        while [ $try -lt 6 ]; do
            for E in $KPROBES; do
                echo "-:kprobes/$E" >> "$T/kprobe_events" 2>/dev/null
            done
            grep -q 'kprobes/[pr]vfs_write' "$T/kprobe_events" || return 0
            sleep 0.5
            try=$((try + 1))
        done
        return 1
    done
}

stop_engine() {
    PID=$(engine_pid)
    if [ -n "$PID" ]; then
        kill $PID 2>/dev/null
        # Chờ tối đa 5 giây cho engine thoát, sau đó buộc dừng.
        i=0
        while [ -n "$(engine_pid)" ] && [ $i -lt 10 ]; do
            sleep 0.5
            i=$((i + 1))
        done
        PID=$(engine_pid)
        [ -n "$PID" ] && kill -9 $PID 2>/dev/null && sleep 0.5
    fi
    cleanup_kprobes
}

read CMD

case "$CMD" in
    STATUS)
        status_line
        ;;
    START)
        PID=$(engine_pid)
        if [ -n "$PID" ]; then
            echo "OK:RUNNING:$PID"
            exit 0
        fi
        cleanup_kprobes
        cd "$BASE" || { echo "ERROR:ENGINE_NOT_STARTED"; exit 1; }
        : > "$LOG"
        date +%s > "$RUN_ID_FILE"
        chmod 755 "$ENGINE"
        TRACEE_BPF_FILE=$BASE/tracee.bpf.dev.o "$ENGINE" --build-policy never --trace event=execve --trace event=vfs_write --capture write >> "$LOG" 2>&1 &
        sleep 2
        PID=$(engine_pid)
        [ -n "$PID" ] && echo "OK:RUNNING:$PID" || echo "ERROR:ENGINE_NOT_STARTED"
        ;;
    STOP)
        stop_engine
        echo "OK:STOPPED"
        ;;
    LOGS)
        grep '^BPFROID_DROPPER_ALERT' "$LOG" 2>/dev/null | tail -n 20
        ;;
    POLL)
        # Dùng cho Dashboard: trạng thái + mã lần chạy + cảnh báo kèm số dòng,
        # gộp trong một kết nối. Cặp (RUN, số dòng) định danh duy nhất mỗi cảnh báo.
        status_line
        echo "RUN:$(cat "$RUN_ID_FILE" 2>/dev/null || echo 0)"
        grep -n '^BPFROID_DROPPER_ALERT' "$LOG" 2>/dev/null | tail -n 100
        ;;
    *)
        echo "ERROR:UNKNOWN_COMMAND"
        ;;
esac
