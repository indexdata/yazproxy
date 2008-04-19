#!/bin/sh
# YAZ proxy start/stop init.d script.

# Config/DB
DB=helka
# Port
PORT=9021

PATH=/m1/voyager/yaz/bin:/bin:/usr/bin
export PATH

# Proxy CWD is here. Should be writable by it.
DIR=/m1/voyager/${DB}db/local/yaz
# Proxy Path 
DAEMON=/m1/voyager/yaz/bin/yazproxy

# Proxy PIDFILE. Must be writable by it.
PIDFILE="yazproxy.pid"

# Log file
LOGFILE=yazproxy.log

# Run as this user. Set to empty to keep uid as is
RUNAS=voyager

# Extra args . Config file _WITH_ option
ARGS="-c ${DB}.xml"

if test -n "RUNAS"; then
	ARGS="-u $RUNAS $ARGS"
fi

# Increase number of sockets, if needed
#ulimit -n 1050

# Name, Description (not essential)
NAME=yazproxy
DESC="YAZ proxy $DB"

test -d $DIR || exit 0
test -f $DAEMON || exit 0

set -e

case "$1" in
  start)
	printf "%s" "Starting $DESC: "
	cd $DIR
	$DAEMON -l $LOGFILE -p $PIDFILE $ARGS @:$PORT &
	echo "$NAME."
	;;
  stop)
	printf "%s" "Stopping $DESC: "
	cd $DIR
	if test -f $PIDFILE; then
		kill `cat $PIDFILE`
		rm -f $PIDFILE
		echo "$NAME."
	else
		echo "No PID $PIDFILE"
	fi
	;;
  reload)
	cd $DIR
	if test -f $PIDFILE; then
		kill -HUP `cat $PIDFILE`
	fi
  ;;
  restart|force-reload)
	printf "%s" "Restarting $DESC: "
	cd $DIR
	if test -f $PIDFILE; then
		kill `cat $PIDFILE`
		rm -f $PIDFILE
	fi
	sleep 1
	cd $DIR
	$DAEMON -l $LOGFILE -p $PIDFILE $ARGS @:$PORT &
	echo "$NAME."
	;;
  *)
	N=/etc/init.d/$NAME
	# echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
