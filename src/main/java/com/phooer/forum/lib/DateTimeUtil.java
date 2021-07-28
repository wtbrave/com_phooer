package com.phooer.forum.lib;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * Author: johnny<wtbrave@gmail.com>
 * Date: 2021/7/28 上午11:00
 */
public class DateTimeUtil {
    public static void format() {
        Date one = new Date();

        Calendar  c1 = Calendar.getInstance();
        c1.setTime(one);
        c1.add(Calendar.DATE, -7);

        SimpleDateFormat sdf  =  new SimpleDateFormat("yyyy-MM-dd");
        String  a = sdf.format(one);
        String  b = sdf.format(c1.getTime());
        System.out.println(a);
        System.out.println(b);
    }
}
