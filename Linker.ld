PROVIDE(__image_base = 0x0000000140000000);

SECTIONS
{
	. = __image_base + SIZEOF_HEADERS;
	.text ALIGN(0x1000) :
	{
		KEEP(*(.text.entrypoint))
		*(.text*)
	} 
}
