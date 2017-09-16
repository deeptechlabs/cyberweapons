main(argc,argv)
int argc; char **argv;
{
	int count;

	if (argc==1)
		count = 0;
	else
		count = atoi(argv[1]) + 1;
	while (--count)
		randbyte();
}
