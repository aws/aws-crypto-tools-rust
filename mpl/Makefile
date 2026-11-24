.PHONY: duvet

duvet:
	../scripts/resolve-spec.sh
	@test -e spec || ln -s ../spec spec
	rm -rf .duvet/reports .duvet/requirements
	duvet report
