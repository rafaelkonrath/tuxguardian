PARTS=daemon frontend module

IS_ROOT=$(shell if [ `id -u` != "0" ]; then echo no; else echo yes; fi)

ifeq ($(IS_ROOT), yes)
all:
	@echo -e "\n\nCompiling and installing the frontend\n------------------------------------------------"; \
	cd frontend; qmake tg-frontend.pro; make; cd ..;

	@echo -e "\n\nCompiling the daemon\n------------------------------------------------"; \
	cd daemon; make; 
	@echo -e "\n\nInstalling the daemon\n------------------------------------------------"; \
	cd daemon; make install; 

	@echo -e "\n\nCompiling the module\n------------------------------------------------"; \
	cd module; make; 
	@echo -e "\n\nInstalling the module\n------------------------------------------------"; \
	cd module; make install;

	@echo -e "\n\n\n\nSuccess! To start TuxGuardian:"
	@echo -e "---------------------------------"
	@echo -e "            (for more information, please visit tuxguardian.sf.net)\n"
	@echo -e "\t$$ su"
	@echo -e "\t   <enter root password>"
	@echo -e "\t$$ tg-daemon &"
	@echo -e "\t$$ modprobe tuxg"
	@echo -e "\t$$ tg-frontend &\n"

clean:
	@for i in $(PARTS); do \
	echo -e "\n\nCleaning the "$$i"\n------------------------------------------------"; \
	cd $$i; make clean; cd ..; \
	done
uninstall: 
	@echo -e "\n\nUninstalling the frontend\n------------------------------------------------"; \
	cd frontend; make distclean; cd ..;

	@echo -e "\n\nUninstalling the daemon\n------------------------------------------------"; \
	cd daemon; make uninstall; cd ..;

	@echo -e "\n\nUninstalling the module\n------------------------------------------------"; \
	cd module; make uninstall;
install:
	@echo -e "No need to 'make install'. Just type 'make'"
else
all:
	@echo "You must be root to compile and install!"
	@exit 1
clean:
	@echo "You must be root to clear!"
	@exit 1
install:
	@echo -e "No need to 'make install'. Just type 'make'"
uninstall:
	@echo "You must be root to uninstall!"
	@exit 1
endif



