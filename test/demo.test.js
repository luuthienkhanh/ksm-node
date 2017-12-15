const test = require('ava')
const path = require('path')
const Demo = require('../src/demo')

test('test sum method', t => {
    const demo = new Demo(2, 5) /* ? */
    const sum = demo.sum() /* ? */
    t.is(sum, 7, '2 + 5 phai bang 7')
})

test('test concat method', t => {
    const demo = new Demo('I', 'You')
    const str = demo.concat()
    t.is(str, 'I love You', 'Phai bang = "I love You"')
})

test('test isEqual', t => {
    const demo = new Demo('Bible', 'Bible')
    const isEqual = demo.isEqual()
    t.true(isEqual, 'Chuoi Bible phai bang Bible')
})


// Luu y co tu khoa async truoc t
test('test async func', async t => {
    const demofile = path.join(__dirname, '../ksm', 'demo.txt') /* ? */
    // Duong dan tren la no copy cai project minh vao cho khac de chay
    const demo = new Demo('', '')
    try {
        const demoText = await demo.hamBatDongBo(demofile)
        console.log(demoText)
        // Minh se test cho nay xem ham chay dung khong
        // No se kiem tra noi dung file text co phai la Hello World hay khong
        // Neu co gi sai no bao mau do minh biet lien
        t.is(demoText, 'Hello Worlds')
    } catch (err) {
        console.log(err.message)
    }
})