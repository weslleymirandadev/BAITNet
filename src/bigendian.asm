%macro BE16 1
    db (((%1) >> 8) & 0xFF), ((%1) & 0xFF)
%endmacro

%macro BE32 1
    db (((%1) >> 24) & 0xFF), (((%1) >> 16) & 0xFF), (((%1) >> 8) & 0xFF), ((%1) & 0xFF)
%endmacro

%macro BE64 1
    db (((%1) >> 56) & 0xFF), (((%1) >> 48) & 0xFF), (((%1) >> 40) & 0xFF), (((%1) >> 32) & 0xFF), \
       (((%1) >> 24) & 0xFF), (((%1) >> 16) & 0xFF), (((%1) >> 8) & 0xFF), ((%1) & 0xFF)
%endmacro
