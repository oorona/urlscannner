import curses
import redis
import json
import os
import sys 
from textwrap import wrap
from dotenv import load_dotenv

# --- Configuration ---
dotenv_path_options = [
    os.path.join(os.getcwd(), '.env'),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
]
loaded_dotenv_path = None
for path_option in dotenv_path_options:
    if os.path.exists(path_option):
        print(f"Loading .env file from: {path_option}")
        load_dotenv(dotenv_path=path_option)
        loaded_dotenv_path = path_option
        break
if not loaded_dotenv_path:
    print("No .env file found. Using system environment variables or defaults.")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD_ENV = os.getenv("REDIS_PASSWORD")
REDIS_PASSWORD = REDIS_PASSWORD_ENV if REDIS_PASSWORD_ENV else None

SUGGESTED_PATTERNS = [
    "urlscan:*", 
    "urlscan:full_assessment_cache:*",
    "urlscan:domain_assessment_cache:*",
    "urlscan:domain_step_cache:*",
]
DEFAULT_KEY_PATTERN = os.getenv("REDIS_MANAGER_DEFAULT_PATTERN", SUGGESTED_PATTERNS[0])
KEYS_PER_PAGE = 15

r_conn = None 
redis_is_connected_main = False

# --- Curses Helper Functions ---

def display_keys_list(stdscr, keys, current_page, total_pages, selected_index, pattern, status_msg=""):
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    title = f"Redis Key Manager - Pattern: {pattern} (Page {current_page + 1}/{total_pages})"
    if len(title) >= w: title = title[:w-1]
    try: stdscr.addstr(0, (w - len(title)) // 2 if w > len(title) else 0, title, curses.A_BOLD)
    except curses.error: pass

    start_index = current_page * KEYS_PER_PAGE
    end_index = start_index + KEYS_PER_PAGE
    displayable_keys = keys[start_index:end_index]

    for i, key_item in enumerate(displayable_keys):
        display_str = key_item
        if len(display_str) > w - 4: display_str = display_str[:w - 7] + "..."
        
        # Determine base attribute (color)
        current_attr = curses.A_NORMAL
        if curses.has_colors():
            if "domain_assessment_cache" in key_item: current_attr = curses.color_pair(3)
            elif "full_assessment_cache" in key_item: current_attr = curses.color_pair(4)
            elif "domain_step_cache" in key_item: current_attr = curses.color_pair(5)
        
        # If this item is selected, combine with A_REVERSE
        if start_index + i == selected_index:
            current_attr |= curses.A_REVERSE 
        
        try:
            stdscr.addstr(i + 2, 2, display_str, current_attr)
        except curses.error: # Handle trying to write off screen
            pass


    instructions = "↑/↓: Select | ←/→: Page | Enter: View | d: Del | r: Refresh | p: Pattern | q: Quit"
    if len(instructions) >= w: instructions = "↑↓←→Enter,d,r,p,q"
    try:
        stdscr.addstr(h - 2, (w - len(instructions)) // 2 if w > len(instructions) else 0, instructions)
    except curses.error:
        pass
    
    if status_msg:
        status_line_y = h - 3
        stdscr.addstr(status_line_y, 2, " " * (w - 4)) # Clear previous status, leave margin
        msg_attr = curses.A_BOLD
        if "Error" in status_msg or "Failed" in status_msg or "No keys" in status_msg :
            if curses.has_colors(): msg_attr |= curses.color_pair(1) # Red
        elif "deleted" in status_msg or "refreshed" in status_msg or "Pattern set" in status_msg or "key(s) found" in status_msg:
            if curses.has_colors(): msg_attr |= curses.color_pair(2) # Green
        try:
            stdscr.addstr(status_line_y, 2, status_msg[:w-3], msg_attr)
        except curses.error:
            pass
    stdscr.refresh()

# display_key_value, get_string_from_user, confirm_delete (remain the same as last correct version)
def display_key_value(stdscr, key_name_disp, value_str):
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    title = f"Value for Key: {key_name_disp}"
    if len(title) >= w: title = title[:w-1]
    try: stdscr.addstr(0, (w - len(title)) // 2 if w > len(title) else 0, title, curses.A_BOLD)
    except curses.error: pass
    
    try:
        parsed_json = json.loads(value_str)
        pretty_value = json.dumps(parsed_json, indent=2, sort_keys=True)
    except json.JSONDecodeError: pretty_value = value_str 
    lines = pretty_value.splitlines()
    top_line = 0; max_lines_in_view = h - 4 

    while True:
        stdscr.clear()
        try: stdscr.addstr(0, (w - len(title)) // 2 if w > len(title) else 0, title, curses.A_BOLD)
        except curses.error: pass
        line_num_display_offset = 2
        for i in range(max_lines_in_view):
            actual_line_index = top_line + i
            if actual_line_index < len(lines):
                line_content = lines[actual_line_index]
                wrapped_sublines = wrap(line_content, w - 4) 
                for subline in wrapped_sublines:
                    if line_num_display_offset < h - 2:
                        try: stdscr.addstr(line_num_display_offset, 2, subline[:w-3]); line_num_display_offset +=1
                        except curses.error: break 
                    else: break
                if line_num_display_offset >= h - 2: break
            else: break
        val_instructions = "Esc/b/q: Back | ↑/↓: Scroll Value"
        if len(val_instructions) >=w : val_instructions = "Esc/b/q,↑↓"
        stdscr.addstr(h - 2, (w - len(val_instructions)) // 2 if w > len(val_instructions) else 0, val_instructions)
        stdscr.refresh()
        key_press_val_view = stdscr.getch()
        if key_press_val_view in [curses.KEY_ESCAPE, ord('b'), ord('B'), ord('q'), ord('Q')]: break
        elif key_press_val_view == curses.KEY_UP:
            if top_line > 0: top_line -= 1
        elif key_press_val_view == curses.KEY_DOWN:
            if top_line < len(lines) - max_lines_in_view : top_line += 1

def get_string_from_user(stdscr, prompt_string, default_text=""):
    h, w = stdscr.getmaxyx()
    prompt_y = h - 4 
    suggestion_line_y = h - 3
    stdscr.addstr(suggestion_line_y, 2, " " * (w - 3)) 
    sugg_text = "Suggestions: " + " | ".join([f"{i+1}) {p}" for i, p in enumerate(SUGGESTED_PATTERNS)])
    stdscr.addstr(suggestion_line_y, 2, sugg_text[:w-3])
    stdscr.addstr(prompt_y, 2, " " * (w - 3))
    stdscr.addstr(prompt_y, 2, prompt_string)
    stdscr.refresh()
    curses.echo(); curses.curs_set(1); stdscr.nodelay(False)
    input_start_x = 2 + len(prompt_string)
    if input_start_x >= w - 2: input_start_x = w - 2 
    max_input_len = w - input_start_x - 2 
    if max_input_len < 1: max_input_len = 1
    input_bytes = stdscr.getstr(prompt_y, input_start_x, max_input_len)
    input_str = input_bytes.decode(encoding="utf-8", errors="ignore").strip()
    curses.noecho(); curses.curs_set(0); 
    stdscr.addstr(prompt_y, 2, " " * (w - 3)) 
    stdscr.addstr(suggestion_line_y, 2, " " * (w-3)) 
    return input_str if input_str else default_text

def confirm_delete(stdscr, key_to_delete_conf):
    h, w = stdscr.getmaxyx()
    win_text = f"Delete key: {key_to_delete_conf[:w-20]}?"
    confirm_win_h, confirm_win_w = 5, min(w - 4, max(40, len(win_text) + 4))
    start_y = (h - confirm_win_h) // 2; start_x = (w - confirm_win_w) // 2
    if start_y < 0: start_y = 0
    if start_x < 0: start_x = 0
    confirm_win = curses.newwin(confirm_win_h, confirm_win_w, start_y, start_x)
    confirm_win.border(); confirm_win.addstr(1, 2, win_text, curses.A_BOLD)
    confirm_win.addstr(2, 2, "Are you sure? (y/N)"); confirm_win.refresh()
    curses.curs_set(1); confirm_win.nodelay(False)
    ch = confirm_win.getch(3, (confirm_win_w - 5) // 2 if confirm_win_w > 5 else 1) 
    curses.curs_set(0); del confirm_win; stdscr.touchwin(); stdscr.refresh()
    return ch == ord('y') or ch == ord('Y')

def main_app_loop(stdscr):
    global r_conn, redis_is_connected_main 
    if not redis_is_connected_main:
        stdscr.clear(); stdscr.addstr(0,0, "Redis connection failed. Press any key."); stdscr.getch(); return

    curses.curs_set(0); stdscr.nodelay(False); stdscr.keypad(True)   
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)    # Error
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Success
        curses.init_pair(3, curses.COLOR_BLUE, curses.COLOR_BLACK)   # Domain Assessment Cache
        curses.init_pair(4, curses.COLOR_MAGENTA, curses.COLOR_BLACK)# Full Assessment Cache
        curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK)   # Domain Step Cache

    current_pattern = DEFAULT_KEY_PATTERN
    keys = []; selected_index = 0; current_page = 0; total_pages = 0; status_message = "" 

    def refresh_keys_main():
        nonlocal keys, selected_index, current_page, total_pages, status_message
        try:
            keys = sorted(r_conn.keys(current_pattern)) 
            selected_index = 0; current_page = 0
            if not keys: total_pages = 1; status_message = f"No keys for pattern: '{current_pattern}'"
            else: total_pages = (len(keys) + KEYS_PER_PAGE - 1) // KEYS_PER_PAGE; status_message = f"{len(keys)} key(s) for '{current_pattern}'"
        except redis.exceptions.RedisError as e: keys=[];total_pages=1;status_message=f"Redis Err: {str(e)[:50]}" 
        except Exception as e: keys=[];total_pages=1;status_message=f"Fetch Err: {str(e)[:50]}"
    refresh_keys_main()

    while True:
        display_keys_list(stdscr, keys, current_page, total_pages, selected_index, current_pattern, status_message)
        status_message = "" 
        key_press_main = stdscr.getch()

        if key_press_main == ord('q') or key_press_main == ord('Q'): break
        elif key_press_main == curses.KEY_UP:
            if selected_index > 0:
                selected_index -= 1
                if selected_index < current_page * KEYS_PER_PAGE:
                    current_page = selected_index // KEYS_PER_PAGE
        elif key_press_main == curses.KEY_DOWN:
            if selected_index < len(keys) - 1:
                selected_index += 1
                if selected_index >= (current_page + 1) * KEYS_PER_PAGE:
                     current_page = selected_index // KEYS_PER_PAGE
        elif key_press_main == curses.KEY_LEFT: 
            if current_page > 0: current_page -= 1; selected_index = current_page * KEYS_PER_PAGE 
        elif key_press_main == curses.KEY_RIGHT: 
            if current_page < total_pages - 1: current_page += 1; selected_index = current_page * KEYS_PER_PAGE
            if keys and selected_index >= len(keys): selected_index = len(keys) -1
            elif not keys: selected_index = 0
        
        elif key_press_main == ord('p') or key_press_main == ord('P'):
            new_pattern_input = get_string_from_user(stdscr, f"Enter new pattern (current: '{current_pattern}'):", current_pattern)
            if new_pattern_input.isdigit() and 1 <= int(new_pattern_input) <= len(SUGGESTED_PATTERNS):
                current_pattern = SUGGESTED_PATTERNS[int(new_pattern_input) - 1]
            elif new_pattern_input: current_pattern = new_pattern_input
            refresh_keys_main()
            status_message = f"Pattern set to: {current_pattern}" if new_pattern_input else "Pattern unchanged."

        elif key_press_main == ord('d') or key_press_main == ord('D'):
            if keys and 0 <= selected_index < len(keys):
                key_to_delete_main = keys[selected_index] 
                if confirm_delete(stdscr, key_to_delete_main):
                    try:
                        r_conn.delete(key_to_delete_main); status_message = f"Key '{key_to_delete_main}' deleted."
                        refresh_keys_main() 
                        if selected_index >= len(keys) and len(keys) > 0: selected_index = len(keys) - 1
                        elif not keys: selected_index = 0
                    except redis.exceptions.RedisError as e: status_message = f"Delete Err: {str(e)[:50]}"
                    except Exception as e: status_message = f"Unexpected Delete Err: {str(e)[:50]}"
                else: status_message = "Delete cancelled."
            else: status_message = "No key selected to delete."

        elif key_press_main == curses.KEY_ENTER or key_press_main == 10 or key_press_main == 13:
            if keys and 0 <= selected_index < len(keys):
                selected_key_name_main = keys[selected_index]
                try:
                    key_type = r_conn.type(selected_key_name_main); value_str = ""
                    if key_type == "string": value_str = r_conn.get(selected_key_name_main)
                    elif key_type == "list": value_str = json.dumps(r_conn.lrange(selected_key_name_main, 0, -1)) 
                    elif key_type == "hash": value_str = json.dumps(r_conn.hgetall(selected_key_name_main))
                    elif key_type == "set": value_str = json.dumps(list(r_conn.smembers(selected_key_name_main)))
                    elif key_type == "zset": value_str = json.dumps(r_conn.zrange(selected_key_name_main, 0, -1, withscores=True))
                    else: value_str = f"Unsupported key type: {key_type}"
                    display_key_value(stdscr, selected_key_name_main, value_str if value_str is not None else "(nil)")
                except redis.exceptions.RedisError as e: status_message = f"Fetch Val Err: {str(e)[:50]}"
                except Exception as e: status_message = f"Unexpected Fetch Val Err: {str(e)[:50]}"
            else: status_message = "No key selected."
        
        elif key_press_main == ord('r') or key_press_main == ord('R'):
            refresh_keys_main(); status_message = "Key list refreshed."

if __name__ == "__main__":
    try:
        r_conn = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, password=REDIS_PASSWORD, decode_responses=True)
        r_conn.ping(); redis_is_connected_main = True
        print(f"Successfully connected to Redis: {REDIS_HOST}:{REDIS_PORT} DB:{REDIS_DB}")
    except redis.exceptions.ConnectionError as e: print(f"Error: Could not connect to Redis. Details: {e}")
    except redis.exceptions.AuthenticationError as e: print(f"Error: Redis authentication failed. Details: {e}")
    except Exception as e: print(f"An unexpected error occurred connecting to Redis: {e}")

    if redis_is_connected_main:
        print("Launching Redis Manager TUI..."); curses.wrapper(main_app_loop)
    else:
        print("\nExiting due to Redis connection failure."); input("\nPress Enter to exit...")