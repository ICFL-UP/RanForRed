def help(self):
    url = 'file://' + os.getcwd() + "\\data\\help\\index.html#userman"
    webbrowser.open_new(url)


def load_settings(self):
    try:
        i = 0
        with open(os.getcwd() + "\\data\\config\\regsmart.conf", 'r') as file:
            for line in file:
                if i < 7:
                    (key, val) = line.split()
                    key = key.strip(":")
                    self.db[str(key)].set(int(val))

                elif i > 6 and i < 14:
                    (key, val) = line.split()
                    key = key.strip(":")
                    self.db[str(key)] = val
                elif i == 14:
                    self.business_setting = line.split(":")[1]
                elif i == 15:
                    self.location_setting = line.split(":")[1].split(",")
                i += 1

    except Exception as ee:
        print(ee)
        logging.error('[RegSmart] An error occurred in (load_settings)', exc_info=True,
                      extra={'investigator': 'RegSmart'})
        return "Error occurred"


def update_settings(self, display=None):
    self.rep_log("Saved settings")
    try:
        with open(os.getcwd() + "\\data\\config\\regsmart.conf", 'w') as file:
            final = ""
            b = self.business_setting.strip("\n")
            loc = ""
            for i in self.location_setting:
                if i != "":
                    loc += i.strip("\n") + ","
            loc = loc[:-1]
            j = 0
            for i, k in self.db.items():
                if j < 7:
                    final += i + ": " + str(k.get()) + "\n"
                else:
                    final += i + ": " + k + "\n"
                j += 1
            final += "business_name:" + b + "\n"
            final += "business_address:" + loc
            file.write(final)
        if not display:
            self.display_message("info", "Your settings have been updated successfully")
            self.settings.destroy()
    except Exception as ee:
        logging.error('[RegSmart] An error occurred in (Update settings)', exc_info=True,
                      extra={'investigator': 'RegSmart'})