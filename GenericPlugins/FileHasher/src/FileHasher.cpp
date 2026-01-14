#include "FileHasher.hpp"
#include "Hasher.hpp"
#include "RESTManager.hpp"
#include <filesystem>
#include <fstream>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

namespace fs = std::filesystem;

constexpr int CMD_BUTTON_CLOSE  = 1;
constexpr int CMD_BUTTON_VERIFY = 2;
constexpr int CMD_BUTTON_UPLOAD = 3;

std::string LoadAPIKey()
{
    fs::path keyPath = "APIKey.txt";
    if (!fs::exists(keyPath)) {
        keyPath = "../APIKey.txt";
        if (!fs::exists(keyPath))
            return "";
    }

    std::ifstream file(keyPath);
    std::string key;
    if (file) {
        std::getline(file, key);
        key.erase(std::remove_if(key.begin(), key.end(), [](unsigned char c) { return std::isspace(c) || !std::isprint(c); }), key.end());
    }
    return key;
}

std::string VT_API_KEY;

class FileHasher : public Window, public Handlers::OnButtonPressedInterface, public Handlers::OnListViewItemPressedInterface
{
    Reference<ListView> fileList;
    Reference<Label> lblStatus, lblHash, lblMalicious, lblHarmless;
    Reference<TextField> txtLink; // CHANGED: Label -> TextField (to allow copying)

    Reference<Button> btnVerify;
    Reference<Button> btnUpload;

    fs::path currentDir;
    fs::path selectedFilePath;

  public:
    FileHasher(const fs::path& path) : Window("File Hasher & Scanner", "d:c,w:90%,h:90%", WindowFlags::Sizeable)
    {
        currentDir = path;
        if (currentDir.empty())
            currentDir = ".";
        try {
            if (fs::exists(currentDir) && !fs::is_directory(currentDir))
                currentDir = currentDir.parent_path();
        } catch (...) {
            currentDir = ".";
        }

        // 1. Layout
        auto split = Factory::Splitter::Create(this, "l:0,t:0,r:0,b:3", SplitterFlags::Vertical);

        // 2. Left Panel
        auto leftP                          = Factory::Panel::Create(split, "Files (Recursive)", "x:0,y:0,w:40%");
        fileList                            = Factory::ListView::Create(leftP, "d:c", { "n:File Path,w:60" });
        fileList->Handlers()->OnItemPressed = this;

        // 3. Right Panel
        auto rightP = Factory::Panel::Create(split, "Analysis", "x:0,y:0,w:60%");

        // Verify Button
        btnVerify                              = Factory::Button::Create(rightP, "&Verify Selected", "x:1,y:1,w:20", CMD_BUTTON_VERIFY);
        btnVerify->Handlers()->OnButtonPressed = this;
        btnVerify->SetEnabled(false);

        // Upload Button (Initially Invisible)
        btnUpload                              = Factory::Button::Create(rightP, "&Upload File", "x:24,y:1,w:20", CMD_BUTTON_UPLOAD);
        btnUpload->Handlers()->OnButtonPressed = this;
        btnUpload->SetVisible(false);

        Factory::Label::Create(rightP, "Status:", "x:1,y:4,w:10");
        lblStatus = Factory::Label::Create(rightP, "Select a file...", "x:12,y:4,w:60");

        Factory::Label::Create(rightP, "SHA256:", "x:1,y:6,w:10");
        lblHash = Factory::Label::Create(rightP, "-", "x:12,y:6,w:60");

        Factory::Label::Create(rightP, "Malicious:", "x:1,y:8,w:10");
        lblMalicious = Factory::Label::Create(rightP, "0", "x:12,y:8,w:60");

        Factory::Label::Create(rightP, "Harmless:", "x:1,y:9,w:10");
        lblHarmless = Factory::Label::Create(rightP, "0", "x:12,y:9,w:60");

        Factory::Label::Create(rightP, "Link:", "x:1,y:11,w:10");

        // CHANGED: Create a TextField instead of Label
        txtLink = Factory::TextField::Create(rightP, "-", "x:12,y:11,w:60");
        // txtLink->SetReadOnly(true); // Optional: prevent editing, but allow copying (if supported by your AppCUI version)

        // 4. Bottom Close Button
        Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE)->Handlers()->OnButtonPressed = this;

        PopulateFiles();
    }

    void PopulateFiles()
    {
        fileList->DeleteAllItems();
        try {
            if (fs::exists(currentDir)) {
                auto opts = fs::directory_options::skip_permission_denied;
                for (const auto& entry : fs::recursive_directory_iterator(currentDir, opts)) {
                    try {
                        if (entry.is_regular_file()) {
                            auto relPath = fs::relative(entry.path(), currentDir);
                            fileList->AddItem(relPath.string());
                        }
                    } catch (...) {
                        continue;
                    }
                }
            }
        } catch (...) {
            lblStatus->SetText("Error accessing directory");
        }
    }

    void OnListViewItemPressed(Reference<ListView> lv, ListViewItem item) override
    {
        std::string relPath = std::string(item.GetText(0));
        selectedFilePath    = currentDir / relPath;

        lblStatus->SetText("File selected. Press Verify.");
        lblHash->SetText("-");
        lblMalicious->SetText("-");
        lblHarmless->SetText("-");
        txtLink->SetText("-"); // CHANGED

        btnVerify->SetEnabled(true);
        btnUpload->SetVisible(false);
    }

    void OnButtonPressed(Reference<Button> b) override
    {
        if (b->GetControlID() == CMD_BUTTON_CLOSE) {
            this->Exit();
        } else if (b->GetControlID() == CMD_BUTTON_VERIFY) {
            PerformVerification();
        } else if (b->GetControlID() == CMD_BUTTON_UPLOAD) {
            PerformUpload();
        }
    }

    void PerformVerification()
    {
        VT_API_KEY = LoadAPIKey();
        btnUpload->SetVisible(false);

        if (selectedFilePath.empty())
            return;

        lblStatus->SetText("Hashing...");
        std::string hash;
        if (!Hasher::ComputeSHA256(selectedFilePath.string(), hash)) {
            lblStatus->SetText("Error: Failed to compute hash");
            return;
        }
        lblHash->SetText(hash);

        lblStatus->SetText("Querying VirusTotal...");
        VirusTotalResult res;
        std::string err;

        if (RESTManager::QueryVirusTotal(VT_API_KEY, hash, res, err)) {
            if (res.found) {
                lblStatus->SetText("Analysis Complete");
                lblMalicious->SetText(std::to_string(res.malicious));
                lblHarmless->SetText(std::to_string(res.harmless));

                // CHANGED: Update the TextField
                txtLink->SetText(res.permalink);
            } else {
                lblStatus->SetText("File not found in VT. Upload?");
                lblMalicious->SetText("Unknown");
                lblHarmless->SetText("Unknown");
                txtLink->SetText("-"); // CHANGED

                btnUpload->SetVisible(true);
                btnUpload->SetFocus();
            }
        } else {
            lblStatus->SetText("API Error: " + err);
        }
    }

    void PerformUpload()
    {
        lblStatus->SetText("Uploading file...");
        std::string err;

        if (RESTManager::UploadFile(VT_API_KEY, selectedFilePath.string(), err)) {
            lblStatus->SetText("Scanning file, check again in 60 seconds");
            btnUpload->SetVisible(false);
        } else {
            lblStatus->SetText("Upload Error: " + err);
        }
    }
};

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
{
    if (command == "FileHasher") {
        fs::path root = ".";
        if (currentObject.IsValid()) {
            auto pathU16 = currentObject->GetPath();
            if (!pathU16.empty()) {
                root = fs::path(pathU16);
            }
        }
        auto dlg = new FileHasher(root);
        dlg->Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.FileHasher"] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::Shift | Input::Key::F10;
}
}