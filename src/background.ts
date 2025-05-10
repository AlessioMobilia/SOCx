import { setupContextMenus } from "./background/menus";
import { handleMenuClick } from "./background/menu-handler";
import { handleMessages } from "./background/message-handler";

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setOptions({ enabled: true });
  setupContextMenus();
});

chrome.contextMenus.onClicked.addListener(handleMenuClick);
chrome.runtime.onMessage.addListener(handleMessages);
