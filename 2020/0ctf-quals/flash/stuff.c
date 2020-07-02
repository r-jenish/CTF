typedef struct struc1 {
    void *field0;
    void *field4;
    void *field8;
    void *fieldC;
} struct_1;

void func_bfc01550(void *arg1)
{
    if (dword_80020000 == 0) {
        func_bfc014d0();
    }

    void *arg1pc = arg1->pc;
    struc1 *r1 = func_bfc00744(0x8002000,&arg1pc);

    if (!r1) {
        arg1->pc = r1->field4;
    }

    return;
}

void *func_bfc00744(struct_1 *a1, void *a2)
{
    void *var18 = *a1;
    int flag1 = 0;
    void *rval = 0;

    while ((a1->field4 != var18) && flag1 == 0) {
        int x = ucmp(a2,var18->field0);
        if (x == -1) {
            var18 = var18->field8;
        } else if (x == 1) {
            var18 = var18->fieldC;
        } else if (x == 0) {
            rval = var18->field0;
            flag1 = 1;
        }
    }

    return rval;
}

int ucmp(void **a1, void **a2) {
   if (*a1 == *a2) return 0;
   if (*a1 < *a2)  return -1;
   return 1;
}


flagcheck2 (char *a0, char *a1, int a2)
{
    memmove(a0,a1,a2);
}

struct some1 {
    uint16_t len;
    uint32_t field_4 = 0;
    uint16_t *ptr1;
    uint32_t field_C = 0x80018000;
    uint16_t field_10 = 0x80020000;
    uint16_t *field_14 = 0x80018000;
    char *   fstr;
};

struct some1 gsvar;

uint16_t pop_sub_80000710(void)                     // pop maybe
{
    if (gsvar->field_C == gsvar->field_14) {
        return 0;
    }

    gsvar->field_14--;
    return *gsvar->field_14;
}

push_sub_80000794(uint16_t a0)                       // push maybe
{
    if (gsvar->field_10 >= gsvar->field_14) {
        *gsvar->field_14 = a0;
        gsvar->field_14++;
    }
}

void fn_8000081c (void)
{
    int var_38 = 0;
    uint16_t var_34;
    uint16_t var_32;
    uint16_t var_20;
    uint16_t var_1E;

    while (var_38 == 0) {
        var_34 = *gsvar->ptr1;
        gsvar->ptr1++;
        switch(var_34) {
            case 0:                     // 0 arg
                var_E = pop();
                var_C = pop();
                push((var_E + var_C) & 0xffff);
                break;
            case 1:                     // 0 arg
                var_12 = pop();
                var_10 = pop();
                push((var_12 - var_10) & 0xffff);
                break;
            case 2:                     // 0 arg
                var_16 = pop();
                var_14 = pop();
                gsvar->field_4 = var_16 * var_14;
                break;
            case 3:                     // 0 arg
                var_18 = pop();
                push((var_18 % gsvar->field_4) & 0xffff);
                break;
            case 4:     // le                       // 0 arg
                var_1C = pop();
                var_1A = pop();
                push (var_1C < var_1A);
                break;
            case 5:     // eq                       // 0 arg
                var_20 = pop_sub_80000710();
                var_1E = pop_sub_80000710();
                t_v0 = (var_1E ^ var_20);
                push_sub_80000794(t_v0 == 0);
                break;
            case 6:                     // 1 arg
                uint32_t var_28 = (int32_t)*gsvar->ptr1;
                gsvar->ptr1++;
                var_24 = pop_sub_80000710();
                if (var_24 != 0) {
                    // 0x80000AC0
                    (var_28 >> 31);
                    kind_of_jmp relative;
                }
                break;
            case 7:                     // 1 arg
                uint32_t var_30 = (int32_t)*gsvar->ptr1;
                gsvar->ptr++;
                var_2C = pop();
                if (var_30 == 0) {
                    // jmp
                }
                break;
            case 8:                     // 0 arg
                push(*(uint16_t *)gsvar->fstr);
                gsvar->fstr += 2;
                break;
            case 9: // push imm                     // 1 arg
                var_32 = *gsvar->ptr1;
                gsvar->ptr1++;
                push_sub_80000794(var_32);
                break;
            case 10: // push flen                       // 0 arg
                push_sub_80000794(gsvar->len & 0xffff);
                break;
            case 11:                        // 0 arg
                gsvar->len = (int32_t)pop();
                break;
            case 12:                        // 0 arg
                pop();
                break;
            case 13:                        // 0 arg
                var_38 = 1;
                break;
            default:
                continue;
                break;
        }

    }
}






void *heap_malloc_maybe(int sz)
{
    void *hmstart = 0x80008000;
    int x = *(int *)hmstart;

    if (hmstart == 0 || sz + x >= 0x8000) {
        *(int *)hmstart = 4;
    }

    var_C = hmstart + *(int *)hmstart;
    *(int *)hmstart += sz;

    memset(var_C, 0, sz);
}
