#!/system/bin/sh
# Usage: ./dump_range.sh <pid> <hex_start> <hex_end> <output_file>
# Example: ./dump_range.sh 12267 714b2b0000 7167733000 dump.bin

PID=$1
START=$((16#$2))
END=$((16#$3))
OUT=$4
CHUNK=$((64 * 1024 * 1024))

if [ -z "$PID" ] || [ -z "$OUT" ]; then
    echo "Usage: $0 <pid> <hex_start> <hex_end> <output>"
    exit 1
fi

> "$OUT"
cur=$START
seq=0

while [ $cur -lt $END ]; do
    nxt=$(($cur + $CHUNK))
    [ $nxt -gt $END ] && nxt=$END
    cur_hex=$(printf "%x" $cur)
    nxt_hex=$(printf "%x" $nxt)
    size=$(($nxt - $cur))
    echo "[$seq] $cur_hex -> $nxt_hex  ($(($size / 1024 / 1024))MB)"
    ./xpida_cli dump $PID $cur_hex $nxt_hex >> "$OUT"
    rc=$?
    [ $rc -ne 0 ] && echo "  warn: rc=$rc"
    cur=$nxt
    seq=$(($seq + 1))
done

total=$(wc -c < "$OUT")
echo "done: $seq chunks, $total bytes -> $OUT"
