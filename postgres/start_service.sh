#!/bin/sh

usage()
{
    echo ""
    echo "$1"
    echo "\t-h --help"
    echo "\t\tprint this message"
    echo "\tpostgres"
    echo "\t\tlaunch postgres service"
    echo "\tpgadmin4"
    echo "\t\tlaunch pgadmin4 service"
}

SCRIPT="$0"
POSTGRES=false
PGADMIN4=false

while [ "$1" != "" ]; do
    PARAM=`echo $1 | awk -F= '{print $1}'`
    VALUE=`echo $1 | awk -F= '{print $2}'`
    case $PARAM in
        -h | --help)
            usage "$SCRIPT"
            exit
            ;;
        postgres)
            POSTGRES=true
            ;;
        /bin/sh | /bin/bash | bash | sh)
            exec "$PARAM"
            ;;
        pgadmin4)
            PGADMIN4=true
            ;;
        *)
            echo "ERROR: unknown parameter \"$PARAM\""
            usage "$SCRIPT"
            exit 1
            ;;
    esac
    shift
done

if [ "$POSTGRES" = true ] ; then
    /usr/local/bin/docker-entrypoint.sh postgres -c config_file=/etc/postgresql.conf &
fi

if [ "$PGADMIN4" = true ] ; then
    /usr/local/bin/pgadmin4-entrypoint.sh pgadmin4
fi

