# cyimmu_fuzz

* To run with Docker

```
	docker build . --tag cim_fuzz

	# To test binaries (run launcher)
	# 	with file input (add the --infile option)
	# 	with a limited time (300 seconds in this example, 0 for no timeout)
	python launcher.py --cbpath ./cbs --dummy --workpath /tmp/tdir --timeout 300 --port 7777 --infile -- CB_ARGs


	# To check UI
	ssh -L 8000:localhost:7777 enginIP


	# For debugging:
	docker run --entrypoint /bin/bash -v ~/cbs:/cbs -v ~/input:/input -v ~/output:/sync --rm -it cyimmu_fuzz 
	# To run shim
	docker run --rm -v data_dir:/input -v outputdir:/output afl \
    	python shim.py --cbname /input/cb --qemu 
	
	# To check status
	sudo docker exec -it container_id /bin/bash 	
```
