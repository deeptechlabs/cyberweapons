/*
 This is a copy-paste hijack that removes breakable invisible characters
 for a clean copy/paste experience.
 */


document.oncopy = alter_copy;

function alter_copy() {
    var body_element = document.getElementsByTagName('body')[0];
    var selection = window.getSelection();
    var sel_text = selection.toString().replace(/\u200b/gi, '');

    var newDiv = document.createElement('div');
    newDiv.style.position = 'absolute';
    newDiv.style.left = '-99999px';

    body_element.appendChild(newDiv);
    newDiv.innerHTML = sel_text;
    selection.selectAllChildren(newDiv);
    window.setTimeout(function () {
        body_element.removeChild(newDiv);
    }, 0);
}
