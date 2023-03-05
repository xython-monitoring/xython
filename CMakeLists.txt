cmake_minimum_required(VERSION 3.4)
project(xython)

install(DIRECTORY xymon/gifs DESTINATION share/xython)

set(XYTHON_ETC "/etc/xython")
set(XYTHON_VAR "var/lib/xython")
set(XYTHON_TOPDIR "lib/xython")
set(CGIDIR "lib/xython/cgi-bin")
set(XYTHON_HOME "lib/xython/server")
set(XYTHON_TMP "/var/lib/xython/tmp")

configure_file(etc/xymonserver.cfg.in ${PROJECT_SOURCE_DIR}/etc/xymonserver.cfg)

#file(GENERATE OUTPUT ${PROJECT_SOURCE_DIR}/xymonserver.cfg INPUT
#	${PROJECT_SOURCE_DIR}/etc/xymonserver.cfg.in)
	#	[=[XYMONVAR=$<XYTHON_VAR>
	#XYTEST=4
	#]=]
	#)

install(FILES etc/analysis.cfg DESTINATION ${XYTHON_ETC})
install(FILES etc/xymonmenu.cfg DESTINATION ${XYTHON_ETC})
install(FILES etc/xymonserver.cfg DESTINATION ${XYTHON_ETC})
install(DIRECTORY xymon/web DESTINATION ${XYTHON_ETC})
install(DIRECTORY DESTINATION /${XYTHON_VAR})
install(DIRECTORY DESTINATION /${XYTHON_VAR}/hist)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/histlogs)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/hostdata)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/acks)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/disabled)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/rrd)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/logs)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/data)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/tmp)
install(DIRECTORY DESTINATION /${XYTHON_VAR}/www)
install(DIRECTORY DESTINATION ${XYTHON_TOPDIR})
install(DIRECTORY DESTINATION ${CGIDIR})
install(DIRECTORY DESTINATION ${XYTHON_TMP})
install(DIRECTORY DESTINATION ${XYTHON_HOME})
install(FILES xython/xythoncgi.py DESTINATION ${CGIDIR}/)

#file(CREATE_LINK "${XYTHON_ETC}/web"
#	"${CMAKE_CURRENT_SOURCE_DIR}/etc" SYMBOLIC)
#install(FILES eetc DESTINATION ${XYTHON_HOME})
