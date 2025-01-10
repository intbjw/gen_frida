from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ida_hexrays import cfunc_t
    from ida_kernwin import view_mouse_event_t

import idc
import idaapi
import ida_lines
import ida_ida

from ida_idaapi import plugin_t

hook_function_template = '''
function hook_{function_name}() {{
    let base_addr = Module.findBaseAddress("{so_name}");

    Interceptor.attach(base_addr.add(0x{offset:X}), {{
        onEnter: function(args) {{
            console.log(`onEnter {function_name}{args}`);
        }}, onLeave: function(retval) {{
            console.log(`onLeave {function_name}{result}`);
        }}
    }});
}}
'''

inline_hook_template = '''
function hook_0x{offset:X}() {{
    let base_addr = Module.findBaseAddress("{so_name}");

    Interceptor.attach(base_addr.add(0x{offset:X}), {{
        onEnter(args) {{
            console.log(`call 0x{offset:X} {args}`);
        }}
    }});
}}
'''

dlopen_after_template = '''
let android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
if(android_dlopen_ext != null) {{
    Interceptor.attach(android_dlopen_ext, {{
        onEnter: function(args) {{
            let so_name = args[0].readCString();
            if(so_name.indexOf("{so_name}") !== -1) {{
                this.hook = true;
            }}
        }}, onLeave: function(retval) {{
            if(this.hook) {{
                this.hook = false;
                dlopen_todo();
            }}
        }}
    }});
}}

function dlopen_todo() {{
    //todo
}}
'''

init_template = '''
function hook_init() {{
    let linker_name = "linker64";
    let already_hook = false;
    let call_constructor_addr = null;
    if (Process.arch.endsWith("arm")) {{
        linker_name = "linker";
    }}

    let symbols = Module.enumerateSymbolsSync(linker_name);
    for (let i = 0; i < symbols.length; i++) {{
        let symbol = symbols[i];
        if (symbol.name.indexOf("call_constructor") !== -1) {{
            call_constructor_addr = symbol.address;
        }}
    }}

    if (call_constructor_addr != null) {{
        console.log(`get construct address ${{call_constructor_addr}}`);
        Interceptor.attach(call_constructor_addr, {{
            onEnter: function (args) {{
                if(already_hook === false) {{
                    const targetModule = Process.findModuleByName("{so_name}");
                    if (targetModule !== null) {{
                        already_hook = true;
                        init_todo();
                    }}
                }}
            }}
        }});
    }}
}}

function init_todo() {{
    //todo
}}
'''

dump_template = '''
function dump_0x{offset:X}() {{
    let base_addr = Module.findBaseAddress("{so_name}");
    let dump_addr = base_addr.add(0x{offset:X});
    let dump_mem = hexdump(dump_addr, {{length: {length:#x}}});
    console.log(`dump {so_name} + {offset:#x}:\\n${{dump_mem}}`);
}}
'''


def generate_print_args(addr: int):
    args_num = get_args_num(addr)
    tmp = []
    for index in range(args_num):
        tmp.append(f'arg{index}:${{args[{index}]}}')
    return ' '.join(tmp)


def generate_for_func(so_name: str, function_name: str, addr: int):
    # 根据参数个数打印
    args_print = generate_print_args(addr)
    if args_print != '':
        args_print = ' ' + args_print
    # 根据是否有返回值判断是否打印retval
    if has_return(addr):
        ret_print = ' ' + '${retval}'
    else:
        ret_print = ''

    result = hook_function_template.format_map({
        'so_name': so_name,
        'function_name': function_name,
        'offset': get_offset(addr),
        'args': args_print,
        'result': ret_print
    })
    print(result)


def get_offset(addr: int) -> int:
    if ida_ida.idainfo_is_64bit():
        return addr
    else:
        # 可以通过T标志位判断某条指令是 ARM 还是 THUMB
        # ARM 返回 0
        # THUMB 返回 1
        return addr + idc.get_sreg(addr, 'T')


def generate_for_inline(so_name: str, addr: int):
    args_print = '${JSON.stringify(this.context)}'
    if idaapi.is_call_insn(addr):
        # 获取指定索引操作数
        operand = idc.print_operand(addr, 0)
        call_addr = idaapi.get_name_ea(0, operand)
        if call_addr != idaapi.BADADDR:
            # 解析 call 的函数其地址
            # 获取指定索引操作数中的值
            addr = idc.get_operand_value(addr, 0)
            args_print = generate_print_args(addr)
    print(inline_hook_template.format_map(
        {'so_name': so_name, 'offset': get_offset(addr), 'args': args_print}))


def has_return(addr: int) -> bool:
    cfun = idaapi.decompile(addr)  # type: cfunc_t
    has_return = True
    dcl = ida_lines.tag_remove(cfun.print_dcl())  # type: str
    if dcl.startswith('void ') and not dcl.startswith('void *'):
        has_return = False
    return has_return


def get_args_num(addr: int) -> int:
    return len(idaapi.decompile(addr).arguments)


def generate_for_func_by_addr(addr: int):
    so_name = idaapi.get_root_filename()
    function_name = idaapi.get_func_name(addr).replace('.', 'dot_')
    generate_for_func(so_name, function_name, addr)


def generate_for_inline_by_addr(addr: int):
    so_name = idaapi.get_root_filename()
    generate_for_inline(so_name, addr)


def generate_snippet():
    '''
    脚本生成入口
    '''
    # 获取光标所处地址
    addr = idaapi.get_screen_ea()  # type: int
    # 通过获取函数属性取到函数首地址
    start_addr = idc.get_func_attr(addr, idc.FUNCATTR_START)
    if start_addr == addr:
        generate_for_func_by_addr(addr)
    elif start_addr == idc.BADADDR:
        print('不在函数内')
    else:
        generate_for_inline_by_addr(addr)


def generate_init_code():
    so_name = idaapi.get_root_filename()
    print(dlopen_after_template.format_map({'so_name': so_name}))
    print(init_template.format_map({'so_name': so_name}))


def generate_dump_script(start: int, length: int):
    so_name = idaapi.get_root_filename()
    print(dump_template.format_map(
        {'so_name': so_name, 'offset': start, 'length': length}))


class MyViewHooks(idaapi.View_Hooks):

    def view_dblclick(self, view, event: 'view_mouse_event_t'):
        '''
        在汇编界面双击地址
        '''
        widget_type = idaapi.get_widget_type(view)
        if widget_type == idaapi.BWN_DISASM:
            global initialized
            if not initialized:
                initialized = True
                generate_init_code()
            generate_snippet()

    def view_click(self, view, event: 'view_mouse_event_t'):
        '''
        在汇编界面选中一个范围后松开鼠标
        '''
        widget_type = idaapi.get_widget_type(view)
        if widget_type == idaapi.BWN_DISASM:
            start = idc.read_selection_start()
            end = idc.read_selection_end()
            if (start != idaapi.BADADDR) and (end != idaapi.BADADDR):
                length = end - start
                generate_dump_script(start, length)


class GenFridaSnippetHandler(idaapi.action_handler_t):
    '''
    动作处理类，和右键菜单绑定
    - https://hex-rays.com/blog/augmenting-ida-ui-with-your-own-actions/
    '''

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        '''
        点了右键菜单之后会调用这个函数
        '''
        generate_snippet()
        return 1

    def update(self, ctx):
        '''
        AST_ENABLE_ALWAYS 表示可以点击
        '''
        return idaapi.AST_ENABLE_ALWAYS


class GenFridaInitHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        generate_init_code()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class GenFridaDumpHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        start = idc.read_selection_start()
        end = idc.read_selection_end()
        if (start != idaapi.BADADDR) and (end != idaapi.BADADDR):
            length = end - start
            generate_dump_script(start, length)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class GenFridaPlugin(plugin_t):
    # 关于插件的注释
    # 当鼠标浮于菜单插件上方时，IDA左下角所示
    comment = 'frida辅助插件'
    # 帮助信息，我们选择不填
    help = '右键选择生成hook代码后找地方粘贴即可'
    # 插件的特性，是一直在内存里，还是运行一下就退出，等等
    flags = idaapi.PLUGIN_KEEP
    # 插件的名字
    wanted_name = 'GenFridaCode'
    # 快捷键，我们选择置空不弄
    wanted_hotkey = ''

    # 插件刚被加载到IDA内存中 这里适合做插件的初始化工作
    def init(self):
        print('GenFridaCode init')
        # 初始化的时候将动作绑定到菜单
        # 这个函数不支持 kwargs
        # name, label, handler, shortcut=None, tooltip=None, icon=-1, flags=0
        gen_frida_init_action_desc = idaapi.action_desc_t(
            'my:gen_frida_init', '生成frida hook init代码', GenFridaInitHandler(), '', '生成frida hook init代码')
        idaapi.register_action(gen_frida_init_action_desc)
        gen_frida_snippet_action_desc = idaapi.action_desc_t(
            'my:gen_frida_snippet', '生成frida hook代码', GenFridaSnippetHandler(), '', '生成frida hook代码')
        idaapi.register_action(gen_frida_snippet_action_desc)
        gen_frida_dump_action_desc = idaapi.action_desc_t(
            'my:gen_frida_dump', '生成frida hook dump代码', GenFridaDumpHandler(), '', '生成frida hook dump代码')
        idaapi.register_action(gen_frida_dump_action_desc)
        global my_ui_hooks
        my_ui_hooks = MyUIHooks()
        my_ui_hooks.hook()
        return idaapi.PLUGIN_KEEP

    # 插件运行中 这里是主要逻辑
    def run(self, arg: int):
        print('GenFridaCode run')
        global my_view_hooks
        my_view_hooks = MyViewHooks()
        my_view_hooks.hook()

    # 插件卸载退出的时机 这里适合做资源释放
    def term(self):
        print('GenFridaCode term')


class MyUIHooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(
                widget, popup_handle, 'my:gen_frida_init', 'GenFrida/')
            idaapi.attach_action_to_popup(
                widget, popup_handle, 'my:gen_frida_snippet', 'GenFrida/')
            idaapi.attach_action_to_popup(
                widget, popup_handle, 'my:gen_frida_dump', 'GenFrida/')


initialized = False
# 注册插件


def PLUGIN_ENTRY():
    return GenFridaPlugin()

# 原作者 https://github.com/Pr0214 https://t.zsxq.com/05IEynQVV
# 修改者 https://github.com/SeeFlowerX https://t.zsxq.com/05E2VBuNj
# 地址 https://gist.github.com/SeeFlowerX/41b7f45913eba9d1dff6fd47c2502b13

# IDA插件，用于生成 frida hook 代码，放入plugins目录后，手动在插件菜单激活然后右键双击、选中释放；或者直接在汇编界面右键使用，选择GenFrida
