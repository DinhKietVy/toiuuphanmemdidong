#!/system/bin/sh
# BPFroid bridge handler: `toybox nc -L` chạy script này một lần cho mỗi kết nối.
#
# Lệnh (một dòng):
#   STATUS                      trạng thái engine
#   POLL [<run id> <dòng cuối>] trạng thái + mã lần chạy + cảnh báo MỚI sau <dòng cuối>
#   LOGS                        20 cảnh báo cuối (dùng thủ công)
#   START <token> | STOP <token> điều khiển engine, cần token
#
# Token: app Dashboard sinh ngẫu nhiên và lưu trong thư mục dữ liệu riêng của nó
# (chỉ app đó và root đọc được). Mọi app khác đều kết nối được tới cổng localhost này,
# nên nếu không có token, malware có thể gửi STOP để tắt bộ giám sát.
BASE=/data/local/tmp
ENGINE=$BASE/tracee-android
LOG=$BASE/bpfroid-engine.log
# Engine tự ghi riêng các dòng BPFROID_DROPPER_ALERT / BPFROID_PRIVESC_ALERT vào file này.
ALERTS=$BASE/bpfroid-alerts.log
RUN_ID_FILE=$BASE/bpfroid-run.id
TOKEN_FILE=/data/user/0/com.bpfroid.dashboard/files/bridge.token
KPROBES="pvfs_write rvfs_write pvfs_writev rvfs_writev"
# Giới hạn số cảnh báo trả về mỗi lần POLL; phần còn lại lấy ở lần POLL sau.
POLL_BATCH=500

engine_pid() { /system/bin/pidof tracee-android; }

status_line() {
    PID=$(engine_pid)
    [ -n "$PID" ] && echo "RUNNING:$PID" || echo "STOPPED"
}

run_id() { cat "$RUN_ID_FILE" 2>/dev/null || echo 0; }

authorized() {
    [ -n "$1" ] || return 1
    [ -r "$TOKEN_FILE" ] || return 1
    [ "$1" = "$(cat "$TOKEN_FILE")" ]
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

read CMD ARG1 ARG2

case "$CMD" in
    STATUS)
        status_line
        ;;
    START)
        if ! authorized "$ARG1"; then
            echo "ERROR:UNAUTHORIZED"
            exit 1
        fi
        PID=$(engine_pid)
        if [ -n "$PID" ]; then
            echo "OK:RUNNING:$PID"
            exit 0
        fi
        cleanup_kprobes
        cd "$BASE" || { echo "ERROR:ENGINE_NOT_STARTED"; exit 1; }
        : > "$LOG"
        : > "$ALERTS"
        date +%s > "$RUN_ID_FILE"
        chmod 755 "$ENGINE"
        # Hai signature của paper, trên toàn hệ thống:
        #  write_alert       - eBPF kiểm tra magic bytes của mọi lần ghi ở offset 0 (ELF/DEX/ZIP)
        #  uid_changed_alert - eBPF so UID của mỗi thread giữa hai syscall liên tiếp
        TRACEE_BPF_FILE=$BASE/tracee.bpf.dev.o BPFROID_ALERT_FILE=$ALERTS \
            "$ENGINE" --build-policy never \
            --trace event=write_alert --trace event=uid_changed_alert >> "$LOG" 2>&1 &
        sleep 2
        PID=$(engine_pid)
        [ -n "$PID" ] && echo "OK:RUNNING:$PID" || echo "ERROR:ENGINE_NOT_STARTED"
        ;;
    STOP)
        if ! authorized "$ARG1"; then
            echo "ERROR:UNAUTHORIZED"
            exit 1
        fi
        stop_engine
        echo "OK:STOPPED"
        ;;
    LOGS)
        tail -n 20 "$ALERTS" 2>/dev/null
        ;;
    POLL)
        # Dashboard gửi "POLL <run id nó đang theo> <số dòng cuối đã nhận>".
        # Chỉ trả các dòng sau đó; nếu engine đã chạy lần mới (run id khác) thì trả từ đầu.
        RUN=$(run_id)
        SINCE=0
        case "$ARG2" in
            ''|*[!0-9]*) ;;
            *) [ "$ARG1" = "$RUN" ] && SINCE=$ARG2 ;;
        esac
        status_line
        echo "RUN:$RUN"
        grep -n '' "$ALERTS" 2>/dev/null | tail -n +$((SINCE + 1)) | head -n $POLL_BATCH
        ;;
    *)
        echo "ERROR:UNKNOWN_COMMAND"
        ;;
esac
