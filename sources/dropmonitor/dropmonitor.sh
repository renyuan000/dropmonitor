#!/bin/sh
#
# chkconfig: 345 50 83
# description: optimezor tcp speed 
#
### BEGIN INIT INFO
# Short-Description: Trigger processlist start-up
# Description: Trigger processlist start-up
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

[ -e /etc/sysconfig/processlist ] && . /etc/sysconfig/processlist


PROCNAME=dropmonitor
PROCNAME_PATH=/usr/local/${PROCNAME}/module/${PROCNAME}.ko

RETVAL=0
status()
{
	lsmod |grep ${PROCNAME} 1>/dev/null 2>&1
	RET=$?
#	[ $RET -eq 0 ] && echo ${PROCLIST} is loaded !! || echo  ${PROCLIST} is not loaded !!
	if [ $RET -eq 0 ] ; then
		echo ${PROCNAME} is loaded !!
	else
		echo  ${PROCNAME} is not loaded !!
	fi	

	return $RET
}
load()
{
	insmod ${PROCNAME_PATH}	2>/dev/null
	RETVAL=$?
	if [ $RETVAL = '0' ]; then
		success; echo
	else
		failure; echo 
		status
		echo 
	fi
	return $RETVAL
}

unload()
{
	rmmod ${PROCNAME} 2>/dev/null
	RETVAL=$?
	[ $RETVAL -eq 0 ] && success  || failure 
	return $RETVAL
}

start()
{
	echo -ne $"Starting ${PROCNAME} module: "
	load
	return $RETVAL
}

stop()
{
	# FIXME If somebody figures out how to disable the K* script
	echo -ne "Stopping ${PROCNAME} module:"
	unload
	echo 
	if [ $RETVAL = '1' ]; then
		status
		echo 
	fi
	return $RETVAL
}


case "$1" in
  start|load)
	start
	;;
  stop|unload)
	stop
	;;
  status)
	status
	;;
  reload|restart)
	stop
	start
	;;
  *)
	echo $"Usage: $0 {start|stop|load|reload|restart|unload|status}"
	exit 3
	;;
esac

exit $RETVAL
