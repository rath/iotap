#!/bin/bash
# Runs the live checks in a Terminal.app window, where sudo can ask for Touch ID, which it cannot
# inside tmux or without a terminal:
#
#     open -a Terminal scripts/live/macos.command
#
# When the run is over, target/live/done holds its exit status, and target/live/run.log its
# verdicts.
cd "$(dirname "$0")/../.." || exit 2
mkdir -p target/live
rm -f target/live/done
echo "iotap's live checks: sudo asks once, for Touch ID or the password."
status=2
if sudo -v; then
  python3 scripts/live/run.py
  status=$?
fi
sudo -k
echo "$status" > target/live/done
echo "Finished with exit status $status. This window can be closed."
