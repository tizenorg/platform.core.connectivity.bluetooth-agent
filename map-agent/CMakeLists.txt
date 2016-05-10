CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(bluetooth-map-agent C)

SET(SRCS bluetooth_map_agent.c bluetooth_map_sms.c bluetooth_map_email.c map_bmessage.c)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs_map_agent
		REQUIRED
		dlog msg-service email-service tapi vconf gio-2.0)

FOREACH(flag ${pkgs_map_agent_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIC -Wall -Werror")

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_map_agent_LDFLAGS})

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/org.bluez.map_agent.service
		DESTINATION share/dbus-1/services)
