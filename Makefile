###############################################################################
# Author: Samuel Jero <sjero@purdue.edu>
###############################################################################
all:
	make -C proxy
	make -C monitor
	make -C state_searcher

clean:
	make -C proxy 		clean
	make -C monitor		clean
	make -C state_searcher	clean
